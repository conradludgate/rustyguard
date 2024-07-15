use std::net::UdpSocket;

use base64ct::{Base64, Encoding};
use clap::Parser;
use rustyguard::{Config, Message, Peer, Sessions};
use x25519_dalek::{PublicKey, StaticSecret};

/// 16-byte aligned packet of 2048 bytes.
/// MTU is assumed to be in the range of 1500 or so, so 2048 should be sufficient.
#[repr(align(16))]
struct AlignedPacket([u8; 2048]);

#[derive(clap::Parser)]
struct Args {
    #[arg(long)]
    peer: Vec<String>,

    #[arg(long, short)]
    port: u16,

    #[arg(long, short)]
    key: Option<String>,
}

fn main() {
    let args = Args::parse();

    let private_key = match args.key {
        Some(key) => {
            let pk = Base64::decode_vec(&key).unwrap();
            let private_key = StaticSecret::from(<[u8; 32]>::try_from(pk).unwrap());
            println!(
                "public key: {}",
                Base64::encode_string(PublicKey::from(&private_key).as_bytes())
            );
            private_key
        }
        None => {
            let private_key = StaticSecret::random();
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
    };

    let mut peers = vec![];
    for peer in args.peer {
        let pk = Base64::decode_vec(&peer).unwrap();
        let peer_pk = PublicKey::from(<[u8; 32]>::try_from(pk).unwrap());
        peers.push(Peer::new(peer_pk, None));
    }

    let config = Config::new(private_key, peers);
    let mut sessions = Sessions::new(config);

    let endpoint = UdpSocket::bind(("0.0.0.0", args.port)).unwrap();
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
