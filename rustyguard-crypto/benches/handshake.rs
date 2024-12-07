use divan::Bencher;
use rand::{rngs::ThreadRng, thread_rng, Rng, RngCore};
use rustyguard_crypto::{
    decrypt_handshake_init, encrypt_handshake_init, encrypt_handshake_resp, EphemeralPrivateKey,
    HandshakeState, Key, StaticInitiatorConfig, StaticPeerConfig, StaticPrivateKey,
};
use tai64::Tai64N;

fn main() {
    divan::main()
}

fn gen_sk(r: &mut ThreadRng) -> StaticPrivateKey {
    let mut b = [0u8; 32];
    r.fill_bytes(&mut b);
    StaticPrivateKey::from_array(&b)
}

#[divan::bench(sample_count = 100, sample_size = 100)]
fn handshake(b: Bencher) {
    b.with_inputs(|| {
        let ssk_i = gen_sk(&mut thread_rng());
        let ssk_r = gen_sk(&mut thread_rng());
        let spk_i = ssk_i.public_key();
        let spk_r = ssk_r.public_key();
        let mut psk = Key::default();
        thread_rng().fill_bytes(&mut psk);

        let mut hs = HandshakeState::default();
        let init = encrypt_handshake_init(
            &mut hs,
            &StaticInitiatorConfig::new(ssk_i),
            &StaticPeerConfig::new(spk_r, Some(psk), None),
            &EphemeralPrivateKey::generate(&mut thread_rng()),
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
        assert_eq!(decrypted.static_key().as_bytes(), peer.key.as_bytes());
        encrypt_handshake_resp(
            &mut hs,
            decrypted,
            &EphemeralPrivateKey::generate(&mut thread_rng()),
            &peer,
            thread_rng().gen(),
            None,
        )
    })
}
