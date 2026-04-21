#![no_main]

use std::{fmt::Debug, net::SocketAddr};

use libfuzzer_sys::{arbitrary::Arbitrary, fuzz_target};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use rustyguard_core::{
    Config, Message, PublicKey, SendMessage, Sessions, StaticPrivateKey, Tai64N,
};
use rustyguard_crypto::{CryptoCore, CryptoPrimatives, Key, StaticPeerConfig};

#[repr(align(16))]
struct AlignedPacket([u8; 2048]);

struct Packet {
    b: Box<AlignedPacket>,
    len: usize,
}

impl Debug for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (&self.b.0[..self.len]).fmt(f)
    }
}

impl<'a> Arbitrary<'a> for Packet {
    fn arbitrary(
        u: &mut libfuzzer_sys::arbitrary::Unstructured<'a>,
    ) -> libfuzzer_sys::arbitrary::Result<Self> {
        let len = u.arbitrary_len::<u8>()?;
        let len = len.min(2048);

        let mut packet = Box::new(AlignedPacket([0; 2048]));
        packet.0[..len].copy_from_slice(u.bytes(len)?);

        Ok(Self { b: packet, len })
    }
}

#[derive(Debug)]
struct FuzzInput {
    src_v4: [u8; 4],
    src_port: u16,
    packet: Packet,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(
        u: &mut libfuzzer_sys::arbitrary::Unstructured<'a>,
    ) -> libfuzzer_sys::arbitrary::Result<Self> {
        let src_v4 = <[u8; 4]>::arbitrary(u)?;
        let src_port = u16::arbitrary(u)?;
        let packet = Packet::arbitrary(u)?;
        Ok(Self {
            src_v4,
            src_port,
            packet,
        })
    }
}

fn gen_sk(r: &mut StdRng) -> StaticPrivateKey {
    let mut b = [0u8; 32];
    r.fill_bytes(&mut b);
    StaticPrivateKey(b)
}

// Forged packets from an arbitrary source address must not redirect the
// responder's outbound endpoint away from the legitimate peer.
fuzz_target!(|input: FuzzInput| {
    let mut input = input;

    let mut rng = StdRng::seed_from_u64(1);
    let server_addr: SocketAddr = "10.0.1.1:1234".parse().unwrap();
    let client_addr: SocketAddr = "10.0.2.1:1234".parse().unwrap();

    let ssk_i = gen_sk(&mut rng);
    let ssk_r = gen_sk(&mut rng);
    let spk_i: PublicKey = CryptoCore::x25519_pubkey(&ssk_i);
    let spk_r: PublicKey = CryptoCore::x25519_pubkey(&ssk_r);
    let mut psk = Key::default();
    rng.fill_bytes(&mut psk);

    let mut config_i = Config::new(ssk_i);
    let peer_r = config_i.insert_peer(StaticPeerConfig::new(spk_r, Some(psk), Some(server_addr)));
    let mut sessions_i = Sessions::new(config_i, &mut rng);

    let mut config_r = Config::new(ssk_r);
    let peer_i = config_r.insert_peer(StaticPeerConfig::new(spk_i, Some(psk), Some(client_addr)));
    let mut sessions_r = Sessions::new(config_r, &mut rng);

    sessions_i.turn(Tai64N::UNIX_EPOCH, &mut rng);
    sessions_r.turn(Tai64N::UNIX_EPOCH, &mut rng);

    let mut buf = Box::new(AlignedPacket([0; 2048]));
    let mut payload = [0u8; 16];
    let init = match sessions_i.send_message(peer_r, &mut payload).unwrap() {
        SendMessage::Maintenance(m) => m,
        SendMessage::Data(_, _) => return,
    };
    let init_bytes = init.data();
    buf.0[..init_bytes.len()].copy_from_slice(init_bytes);
    let resp = match sessions_r.recv_message(client_addr, &mut buf.0[..init_bytes.len()]) {
        Ok(Message::Write(b)) => b.to_vec(),
        _ => return,
    };
    buf.0[..resp.len()].copy_from_slice(&resp);
    let _ = sessions_i.recv_message(server_addr, &mut buf.0[..resp.len()]);

    let mut attacker_addr: SocketAddr =
        SocketAddr::from((std::net::Ipv4Addr::from(input.src_v4), input.src_port));
    if attacker_addr == client_addr {
        attacker_addr.set_port(client_addr.port().wrapping_add(1));
    }

    let _ = sessions_r.recv_message(attacker_addr, &mut input.packet.b.0[..input.packet.len]);

    match sessions_r.send_message(peer_i, &mut payload).unwrap() {
        SendMessage::Data(addr, _) => assert_eq!(addr, client_addr),
        SendMessage::Maintenance(m) => assert_eq!(m.to(), client_addr),
    }
});
