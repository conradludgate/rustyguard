use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use base64ct::{Base64, Encoding};
use ini::Ini;
use iptrie::{Ipv4LCTrieMap, Ipv4Prefix, Ipv4RTrieMap};
use rand::{rngs::OsRng, Rng, TryRngCore};
use rustyguard_core::{Config, DataHeader, Message, PeerId, PublicKey, Sessions, StaticPrivateKey};
use rustyguard_crypto::{AsyncDhOracle, StaticPeerConfig};

use crate::tun::{platform, Device as _, KERNEL_HEADER_LEN};

pub mod tun;

/// Starting buffer position of the IP packet after all headers
/// defined as `max(size_of::<DataHeader>(), KERNEL_HEADER_LEN)`
const IP_PACKET_START: usize = const_max(std::mem::size_of::<DataHeader>(), KERNEL_HEADER_LEN);

/// Starting buffer position where the TUN must be read
pub const TUN_BUF_START: usize = IP_PACKET_START - KERNEL_HEADER_LEN;

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

    pub addrs: Vec<Ipv4Prefix>,

    pub endpoint: Option<String>,
}

impl TunConfig {
    pub fn parse() -> Self {
        // First positional arg overrides the default, so e2e harnesses can
        // point at a rendered config without baking the path into the binary.
        let path = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "rustyguard-tun/test-data/rg.conf".to_string());
        let i = Ini::load_from_file(&path).unwrap();

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
                private_key = StaticPrivateKey((&**key).try_into().unwrap());
            }
            None => {
                private_key = StaticPrivateKey(OsRng.unwrap_err().random());
                let c = private_key.0;
                println!("private key: {}", Base64::encode_string(c.as_ref()));
            }
        }
        println!("public key: {}", Base64::encode_string(&private_key.0));
        private_key
    }

    pub fn build(self) -> (Sessions, Ipv4LCTrieMap<PeerId>) {
        let mut rg_config = Config::new(self.key());

        let mut peer_net = Ipv4RTrieMap::with_root(PeerId::sentinal());
        for peer in self.peers {
            let peer_pk = PublicKey(<[u8; 32]>::try_from(&*peer.key).unwrap());
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

        let sessions = Sessions::new(rg_config, &mut OsRng.unwrap_err());
        (sessions, peer_net)
    }
}

pub enum Write<'a> {
    Outbound(&'a [u8], SocketAddr),
    Inbound(&'a [u8]),
    None,
}

pub async fn handle_extern<'a, O: AsyncDhOracle>(
    sessions: &mut Sessions<O>,
    peer_net: &Ipv4LCTrieMap<PeerId>,
    addr: SocketAddr,
    ep_buf: &'a mut [u8],
) -> Write<'a> {
    // println!("packet from {addr:?}: {:?}", &ep_buf.filled());
    match sessions.async_recv_message(addr, ep_buf).await {
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

            let len_data = buf.len();
            // recv_message wrote the decrypted packet for the TUN
            // of len_data bytes starting at IP_PACKET_START
            // we prepend the kernel header before it if needed
            let tun_buf = &mut ep_buf[TUN_BUF_START..IP_PACKET_START + len_data];
            let (header, packet) = tun_buf
                .split_first_chunk_mut()
                .expect("Enough len for header by definition of TUN_BUF_START");
            *header = platform::Device::get_header_for(packet);

            // and return KERNEL_HEADER || IP_PACKET for the TUN
            return Write::Inbound(tun_buf);
        }

        Ok(Message::Write(buf)) => {
            let len_data = buf.len();
            // println!("sending: {buf:?}");
            return Write::Outbound(&mut ep_buf[..len_data], addr);
        }
    }

    Write::None
}

pub async fn handle_intern<'a, O: AsyncDhOracle>(
    sessions: &mut Sessions<O>,
    peer_net: &Ipv4LCTrieMap<PeerId>,
    reply_buf: &'a mut [u8],
    filled: usize,
) -> Write<'a> {
    let tun_buf = &mut reply_buf[IP_PACKET_START..filled];
    let n = filled - IP_PACKET_START;

    // println!("tun->wg {:02X?}", tun_buf.filled());
    let Ok(ipv4) = packet::ip::v4::Packet::new(tun_buf) else {
        return Write::None;
    };
    // println!("{ipv4:?}");
    let dest = ipv4.destination();
    let (_, peer_idx) = peer_net.lookup(&dest);

    // Packets whose destination doesn't match any peer's AllowedIPs land on
    // the sentinal peer; drop them rather than crashing on send_message.
    if *peer_idx == PeerId::sentinal() {
        return Write::None;
    }

    let pad_to = IP_PACKET_START + n.next_multiple_of(16);
    reply_buf[filled..pad_to].fill(0);

    match sessions
        .async_send_message(*peer_idx, &mut reply_buf[IP_PACKET_START..pad_to])
        .await
        .unwrap()
    {
        rustyguard_core::SendMessage::Maintenance(msg) => {
            let data = msg.data();
            reply_buf[..data.len()].copy_from_slice(data);
            Write::Outbound(&reply_buf[..data.len()], msg.to())
        }
        rustyguard_core::SendMessage::Data(ep, metadata) => {
            /// Size of the WireGuard tag
            const TAG_FOOTER_SIZE: usize = 16;

            /// Starting position of the WireGuard packet to send to a peer
            const WG_PACKET_START: usize = IP_PACKET_START - std::mem::size_of::<DataHeader>();
            // send_message wrote the cypher text at [IP_PACKET_START..pad_to]
            // so the header place is [WG_PACKET_START..IP_PACKET_START]
            // and the footer [pad_to..pad_to + TAG_FOOTER_SIZE].
            let buf = &mut reply_buf[WG_PACKET_START..pad_to + TAG_FOOTER_SIZE];
            metadata.frame_in_place(buf);
            Write::Outbound(buf, ep)
        }
    }
}

/// TODO: replace by max once const stable
const fn const_max(a: usize, b: usize) -> usize {
    if a <= b {
        b
    } else {
        a
    }
}
