use chacha20poly1305::Key;
use divan::Bencher;
use rand::{thread_rng, Rng, RngCore};
use rustyguard_crypto::{
    decrypt_handshake_init, encrypt_handshake_init, encrypt_handshake_resp, HandshakeState,
    StaticInitiatorConfig, StaticPeerConfig,
};
use tai64::Tai64N;
use x25519_dalek::{PublicKey, ReusableSecret, StaticSecret};

fn main() {
    divan::main()
}

#[divan::bench(sample_count = 100, sample_size = 100)]
fn handshake(b: Bencher) {
    b.with_inputs(|| {
        let ssk_i = StaticSecret::random_from_rng(thread_rng());
        let ssk_r = StaticSecret::random_from_rng(thread_rng());
        let spk_i = PublicKey::from(&ssk_i);
        let spk_r = PublicKey::from(&ssk_r);
        let mut psk = Key::default();
        thread_rng().fill_bytes(&mut psk);

        let mut hs = HandshakeState::default();
        let init = encrypt_handshake_init(
            &mut hs,
            &StaticInitiatorConfig::new(ssk_i),
            &StaticPeerConfig::new(spk_r, Some(psk), None),
            &ReusableSecret::random_from_rng(thread_rng()),
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
        assert_eq!(decrypted.static_key(), peer.key);
        encrypt_handshake_resp(
            &mut hs,
            decrypted,
            &StaticSecret::random_from_rng(thread_rng()),
            &peer,
            thread_rng().gen(),
            None,
        )
    })
}
