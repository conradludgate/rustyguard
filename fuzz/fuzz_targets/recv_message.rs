#![no_main]

use std::{fmt::Debug, net::SocketAddr};

use chacha20poly1305::Key;
use libfuzzer_sys::{arbitrary::Arbitrary, fuzz_target};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use rustyguard::{Config, Peer, PublicKey, Sessions, StaticSecret, Tai64N};

/// 16-byte aligned packet of 2048 bytes.
/// MTU is assumed to be in the range of 1500 or so, so 2048 should be sufficient.
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

fuzz_target!(|data: Packet| {
    let mut data = data;

    let mut rng = StdRng::seed_from_u64(1);
    let server_addr: SocketAddr = "10.0.1.1:1234".parse().unwrap();
    let ssk_i = StaticSecret::random_from_rng(&mut rng);
    let ssk_r = StaticSecret::random_from_rng(&mut rng);
    let spk_r = PublicKey::from(&ssk_r);
    let mut psk = Key::default();
    rng.fill_bytes(&mut psk);

    let now = Tai64N::UNIX_EPOCH;

    let peer = Peer::new(spk_r, Some(psk), Some(server_addr));
    let mut config = Config::new(ssk_i);
    let _ = config.insert_peer(peer);
    let mut sessions_i = Sessions::new(config, now, &mut rng);

    _ = sessions_i.recv_message(server_addr, &mut data.b.0[..data.len]);
});
