use chacha20poly1305::Key;
use divan::Bencher;
use rand::{thread_rng, Rng, RngCore};
use rustyguard_crypto::{
    decrypt_handshake_init, encrypt_handshake_init, encrypt_handshake_resp, HandshakeState,
    PrivateKey, StaticInitiatorConfig, StaticPeerConfig, UnparsedPublicKey, X25519,
};
use tai64::Tai64N;

fn main() {
    divan::main()
}

fn pk(s: &PrivateKey) -> UnparsedPublicKey<[u8; 32]> {
    UnparsedPublicKey::new(
        &X25519,
        s.compute_public_key().unwrap().as_ref().try_into().unwrap(),
    )
}

fn gen_sk() -> PrivateKey {
    let mut b = [0u8; 32];
    thread_rng().fill_bytes(&mut b);
    PrivateKey::from_private_key(&X25519, &b).unwrap()
}

#[divan::bench(sample_count = 100, sample_size = 100)]
fn handshake(b: Bencher) {
    b.with_inputs(|| {
        let ssk_i = gen_sk();
        let ssk_r = gen_sk();
        let spk_i = pk(&ssk_i);
        let spk_r = pk(&ssk_r);
        let mut psk = Key::default();
        thread_rng().fill_bytes(&mut psk);

        let mut hs = HandshakeState::default();
        let init = encrypt_handshake_init(
            &mut hs,
            &StaticInitiatorConfig::new(ssk_i),
            &StaticPeerConfig::new(spk_r, Some(psk), None),
            &gen_sk(),
            Tai64N::now(),
            thread_rng().gen(),
            None,
        );

        (
            init,
            StaticInitiatorConfig::new(ssk_r),
            StaticPeerConfig::new(spk_i, Some(psk), None),
        )
    })
    .bench_local_values(|(mut msg, config, peer)| {
        let mut hs = HandshakeState::default();
        let decrypted = decrypt_handshake_init(&mut msg, &mut hs, &config).unwrap();
        assert_eq!(decrypted.static_key().bytes(), peer.key.bytes());
        encrypt_handshake_resp(
            &mut hs,
            decrypted,
            &gen_sk(),
            &peer,
            thread_rng().gen(),
            None,
        )
    })
}
