use base64ct::{Base64, Encoding};
use rand::rngs::OsRng;
use rustyguard::{Config, DataHeader, Message, Peer, PeerId, PublicKey, Sessions, StaticSecret};
use tai64::Tai64N;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::UdpSocket,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = TunConfig::parse();

    let mut rg_config = Config::new(args.key());

    let mut peer_net = iptrie::RTrieMap::with_root(PeerId::sentinal());
    for peer in args.peers {
        let peer_pk = PublicKey::from(<[u8; 32]>::try_from(&*peer.key).unwrap());
        let id = rg_config.insert_peer(Peer::new(
            peer_pk,
            None,
            peer.endpoint.as_ref().and_then(|e| e.parse().ok()),
        ));

        for addr in &peer.addrs {
            peer_net.insert(*addr, id);
        }
    }
    let peer_net = peer_net.compress();

    let mut sessions = Sessions::new(rg_config, Tai64N::now(), &mut OsRng);
    let endpoint = UdpSocket::bind(args.interface.host).await.unwrap();

    let mut buf: Box<AlignedPacket> = Box::new(AlignedPacket([0; 2048]));
    let mut reply_buf = vec![0; 2048];

    let mut config = tun::Configuration::default();
    config
        .address(args.interface.addr.addr())
        .netmask(args.interface.addr.netmask())
        .up();

    let mut dev = tun::create_as_async(&config).unwrap();

    const H: usize = std::mem::size_of::<DataHeader>();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        let mut ep_buf = ReadBuf::new(&mut buf.0);
        let mut tun_buf = ReadBuf::new(&mut reply_buf[H..]);
        tokio::select! {
            _ = tick.tick() => {
                while let Some(msg) = sessions.turn(Tai64N::now(), &mut OsRng) {
                    endpoint.send_to(msg.data(), msg.to()).await.unwrap();
                }
            }
            res = endpoint.recv_buf_from(&mut ep_buf) => {
                let addr = res.unwrap().1;

                // println!("packet from {addr:?}: {:?}", &ep_buf.filled());
                match sessions.recv_message(addr, ep_buf.filled_mut()) {
                    Err(e) => println!("error: {e:?}"),
                    Ok(Message::Noop) => println!("noop"),
                    Ok(Message::HandshakeComplete(_peer, _encryptor)) => {
                        // TODO(conrad): resend queued message.
                        // _encryptor.encrypt_and_frame(payload_buffer)
                        // endpoint.send_to(payload_buffer, addr).await.unwrap()
                    }
                    Ok(Message::Read(peer_idx, buf)) => {
                        if buf.is_empty() {
                            continue;
                        }

                        // println!("wg->tun {buf:02X?}");
                        let Ok(ipv4) = packet::ip::v4::Packet::new(&*buf) else {
                            continue;
                        };
                        // println!("{ipv4:?}");

                        let src_ip = ipv4.source();
                        if *peer_net.lookup(&src_ip).1 != peer_idx {
                            continue;
                        }

                        dev.write_all(buf).await.unwrap();
                    }
                    Ok(Message::Write(buf)) => {
                        // println!("sending: {buf:?}");
                        endpoint.send_to(buf, addr).await.unwrap();
                    }
                }
            }
            res = dev.read_buf(&mut tun_buf) => {
                let n = res.unwrap();

                // println!("tun->wg {:02X?}", tun_buf.filled());
                let Ok(ipv4) = packet::ip::v4::Packet::new(tun_buf.filled()) else {
                    continue;
                };
                // println!("{ipv4:?}");
                let dest = ipv4.destination();
                let (_, peer_idx) = peer_net.lookup(&dest);

                let pad_to = n.next_multiple_of(16);
                tun_buf.put_slice(&[0; 16][..pad_to-n]);

                match sessions.send_message(*peer_idx, tun_buf.filled_mut()).unwrap() {
                    rustyguard::SendMessage::Maintenance(msg) => {
                        endpoint.send_to(msg.data(), msg.to()).await.unwrap();
                        // TODO(conrad): queue up tun_buf to send again later.
                    },
                    rustyguard::SendMessage::Data(ep, metadata) => {
                        let buf = &mut reply_buf[..pad_to + H + 16];
                        metadata.frame_in_place(buf);
                        endpoint.send_to(buf, ep).await.unwrap();
                    }
                }
            }
        }
    }
}

/// 16-byte aligned packet of 2048 bytes.
/// MTU is assumed to be in the range of 1500 or so, so 2048 should be sufficient.
#[repr(align(16))]
struct AlignedPacket([u8; 2048]);

#[derive(knuffel::Decode)]
struct TunConfig {
    #[knuffel(child)]
    interface: TunInterface,

    #[knuffel(children(name = "peer"))]
    peers: Vec<PeerConfig>,
}

#[derive(knuffel::Decode)]
struct TunInterface {
    #[knuffel(child, unwrap(argument, bytes))]
    key: Option<Vec<u8>>,

    #[knuffel(child, unwrap(argument))]
    host: String,

    #[knuffel(child, unwrap(argument, str))]
    addr: ipnet::Ipv4Net,
}

#[derive(knuffel::Decode)]
struct PeerConfig {
    #[knuffel(child, unwrap(argument, bytes))]
    key: Vec<u8>,

    #[knuffel(children(name = "addr"), unwrap(argument, str))]
    addrs: Vec<ipnet::Ipv4Net>,

    #[knuffel(child, unwrap(argument))]
    endpoint: Option<String>,
}

impl TunConfig {
    fn parse() -> Self {
        let config = std::fs::read_to_string("./examples/tun.kdl")
            .expect("examples/tun.kdl file should not be missing");
        knuffel::parse("examples/tun.kdl", &config).unwrap()
    }

    fn key(&self) -> StaticSecret {
        match &self.interface.key {
            Some(key) => {
                let private_key = StaticSecret::from(<[u8; 32]>::try_from(&**key).unwrap());
                println!(
                    "public key: {}",
                    Base64::encode_string(PublicKey::from(&private_key).as_bytes())
                );
                private_key
            }
            None => {
                let private_key = StaticSecret::random_from_rng(OsRng);
                println!(
                    "private key: {}",
                    Base64::encode_string(private_key.as_bytes())
                );
                println!(
                    "public key: {}",
                    Base64::encode_string(PublicKey::from(&private_key).as_bytes())
                );
                private_key
            }
        }
    }
}
