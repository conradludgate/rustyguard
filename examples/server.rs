use std::net::UdpSocket;

use base64ct::Encoding;
use rustyguard::{Config, Message, Peer, Sessions};
use x25519_dalek::{PublicKey, StaticSecret};

/// 16-byte aligned packet of 2048 bytes.
/// MTU is assumed to be in the range of 1500 or so, so 2048 should be sufficient.
#[repr(align(16))]
struct AlignedPacket([u8; 2048]);

fn main() {
    let private_key = StaticSecret::random();
    println!(
        "public key: {}",
        base64ct::Base64::encode_string(PublicKey::from(&private_key).as_bytes())
    );

    let mut peer_pk = [0; 32];
    base64ct::Base64::decode("5stzRvSwl0jxBteouplC3fSnwhKP+pHiaqPJ2OxgjGw=", &mut peer_pk).unwrap();
    let peer_pk = PublicKey::from(peer_pk);

    let config = Config::new(private_key, [Peer::new(peer_pk, None)]);
    let mut sessions = Sessions::new(config);

    let endpoint = UdpSocket::bind("0.0.0.0:0").unwrap();
    println!("addr: {:?}", endpoint.local_addr());

    let mut buf: Box<AlignedPacket> = Box::new(AlignedPacket([0; 2048]));
    loop {
        let (n, addr) = endpoint.recv_from(&mut buf.0).unwrap();
        println!("packet from {addr:?}: {:?}", &buf.0[..n]);
        match sessions.recv_message(addr, &mut buf.0[..n]) {
            Err(err) => println!("error: {err:?}"),
            Ok(Message::Noop) => println!("noop"),
            Ok(Message::Read(buf)) => println!("data: {buf:?}"),
            Ok(Message::Write(buf)) => {
                println!("sending: {buf:?}");
                endpoint.send_to(buf, addr).unwrap();
            }
        }
    }
}
