use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use base64ct::{Base64, Encoding};
use ini::Ini;
use ipnet::Ipv4Net;
use iptrie::{LCTrieMap, RTrieMap};
use rand::{rngs::OsRng, Rng};
use rustyguard_core::{Config, DataHeader, Message, PeerId, PublicKey, Sessions, StaticPrivateKey};
use rustyguard_crypto::StaticPeerConfig;

pub mod tun;

pub const H: usize = std::mem::size_of::<DataHeader>();

/// 16-byte aligned packet of 2048 bytes.
/// MTU is assumed to be in the range of 1500 or so, so 2048 should be sufficient.
#[repr(align(16))]
pub struct AlignedPacket(pub [u8; 2048]);

pub struct TunConfig {
    pub interface: TunInterface,

    pub peers: Vec<PeerConfig>,
}

pub struct TunInterface {
    pub key: Option<Vec<u8>>,

    pub host: SocketAddr,

    pub addr: ipnet::Ipv4Net,
}

pub struct PeerConfig {
    pub key: Vec<u8>,

    pub addrs: Vec<ipnet::Ipv4Net>,

    pub endpoint: Option<String>,
}

impl TunConfig {
    pub fn parse() -> Self {
        let i = Ini::load_from_file("rustyguard-tun/test-data/rg.conf").unwrap();

        let mut interface = None;
        let mut peers = vec![];

        for (sec, prop) in i.iter() {
            match sec {
                Some("Interface") => {
                    let mut key = None;
                    let mut port = 0u16;
                    let mut addr = None;

                    for (k, v) in prop.iter() {
                        match k {
                            "ListenPort" => port = v.parse().unwrap(),
                            "PrivateKey" => key = Some(base64ct::Base64::decode_vec(v).unwrap()),
                            "Address" => addr = Some(v.parse().unwrap()),
                            _ => {}
                        }
                    }

                    interface = Some(TunInterface {
                        key,
                        host: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
                        addr: addr.unwrap(),
                    });
                }
                Some("Peer") => {
                    let mut key = None;
                    let mut addrs = vec![];
                    let mut endpoint = None;

                    for (k, v) in prop.iter() {
                        match k {
                            "PublicKey" => key = Some(base64ct::Base64::decode_vec(v).unwrap()),
                            "AllowedIPs" => addrs.push(v.parse().unwrap()),
                            "Endpoint" => endpoint = Some(v.to_owned()),
                            _ => {}
                        }
                    }

                    peers.push(PeerConfig {
                        key: key.unwrap(),
                        addrs,
                        endpoint,
                    });
                }
                _ => {}
            }
        }

        Self {
            interface: interface.unwrap(),
            peers,
        }
    }

    pub fn key(&self) -> StaticPrivateKey {
        let private_key;
        match &self.interface.key {
            Some(key) => {
                private_key = StaticPrivateKey::from_array((&**key).try_into().unwrap());
            }
            None => {
                private_key = StaticPrivateKey::from_array(&OsRng.gen());
                let c = private_key.as_bytes();
                println!("private key: {}", Base64::encode_string(c.as_ref()));
            }
        }
        println!(
            "public key: {}",
            Base64::encode_string(&private_key.public_key().as_bytes())
        );
        private_key
    }

    pub fn build(self) -> (Sessions, LCTrieMap<Ipv4Net, PeerId>) {
        let mut rg_config = Config::new(self.key());

        let mut peer_net = RTrieMap::with_root(PeerId::sentinal());
        for peer in self.peers {
            let peer_pk = PublicKey::from_array(<&[u8; 32]>::try_from(&*peer.key).unwrap());
            let id = rg_config.insert_peer(StaticPeerConfig::new(
                peer_pk,
                None,
                peer.endpoint
                    .as_ref()
                    .and_then(|e| e.to_socket_addrs().unwrap().find(|s| s.is_ipv4())),
            ));

            for addr in &peer.addrs {
                peer_net.insert(*addr, id);
            }
        }
        let peer_net = peer_net.compress();

        let sessions = Sessions::new(rg_config, &mut OsRng);
        (sessions, peer_net)
    }
}

pub enum Write<'a> {
    Outbound(&'a [u8], SocketAddr),
    Inbound(&'a [u8]),
    None,
}

pub fn handle_extern<'a>(
    sessions: &mut Sessions,
    peer_net: &LCTrieMap<Ipv4Net, PeerId>,
    addr: SocketAddr,
    ep_buf: &'a mut [u8],
) -> Write<'a> {
    // println!("packet from {addr:?}: {:?}", &ep_buf.filled());
    match sessions.recv_message(addr, ep_buf) {
        Err(e) => println!("error: {e:?}"),
        Ok(Message::Noop) => println!("noop"),
        Ok(Message::HandshakeComplete(_encryptor)) => {
            // TODO(conrad): resend queued message.
            // _encryptor.encrypt_and_frame(payload_buffer)
            // endpoint.send_to(payload_buffer, addr).await.unwrap()
        }
        Ok(Message::Read(peer_idx, buf)) => {
            if buf.is_empty() {
                return Write::None;
            }

            // println!("wg->tun {buf:02X?}");
            let Ok(ipv4) = packet::ip::v4::Packet::new(&*buf) else {
                return Write::None;
            };
            // println!("{ipv4:?}");

            let src_ip = ipv4.source();
            if *peer_net.lookup(&src_ip).1 != peer_idx {
                return Write::None;
            }

            return Write::Inbound(buf);
        }
        Ok(Message::Write(buf)) => {
            // println!("sending: {buf:?}");
            return Write::Outbound(buf, addr);
        }
    }

    Write::None
}

pub fn handle_intern<'a>(
    sessions: &mut Sessions,
    peer_net: &LCTrieMap<Ipv4Net, PeerId>,
    reply_buf: &'a mut [u8],
    filled: usize,
) -> Write<'a> {
    let tun_buf = &mut reply_buf[H..filled];
    let n = filled - H;

    // println!("tun->wg {:02X?}", tun_buf.filled());
    let Ok(ipv4) = packet::ip::v4::Packet::new(tun_buf) else {
        return Write::None;
    };
    // println!("{ipv4:?}");
    let dest = ipv4.destination();
    let (_, peer_idx) = peer_net.lookup(&dest);

    let pad_to = H + n.next_multiple_of(16);
    reply_buf[filled..pad_to].fill(0);

    match sessions
        .send_message(*peer_idx, &mut reply_buf[H..pad_to])
        .unwrap()
    {
        rustyguard_core::SendMessage::Maintenance(msg) => {
            let data = msg.data();
            reply_buf[..data.len()].copy_from_slice(data);
            Write::Outbound(&reply_buf[..data.len()], msg.to())
        }
        rustyguard_core::SendMessage::Data(ep, metadata) => {
            let buf = &mut reply_buf[..pad_to + 16];
            metadata.frame_in_place(buf);
            Write::Outbound(buf, ep)
        }
    }
}
