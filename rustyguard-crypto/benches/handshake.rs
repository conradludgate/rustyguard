use divan::Bencher;
use rand::{rng, rngs::ThreadRng, Rng, RngCore};
use rustyguard_crypto::{
    CryptoCore, CryptoPrimatives, DecryptHandshakeInit, EncryptHandshakeInit, EphemeralPrivateKey,
    HandshakeState, Key, SharedSecret, StaticInitiatorConfig, StaticPeerConfig, StaticPrivateKey,
};
use tai64::Tai64N;

fn main() {
    divan::main()
}

fn gen_sk(r: &mut ThreadRng) -> StaticPrivateKey {
    let mut b = [0u8; 32];
    r.fill_bytes(&mut b);
    StaticPrivateKey(b)
}

#[divan::bench(sample_count = 100, sample_size = 100)]
fn handshake(b: Bencher) {
    b.with_inputs(|| {
        let ssk_i = gen_sk(&mut rng());
        let ssk_r = gen_sk(&mut rng());
        let spk_i = CryptoCore::x25519_pubkey(&ssk_i);
        let spk_r = CryptoCore::x25519_pubkey(&ssk_r);
        let mut psk = Key::default();
        rng().fill_bytes(&mut psk);

        let local = StaticInitiatorConfig::new(ssk_i);
        let peer = StaticPeerConfig::new(spk_r, Some(psk), None);
        let request = EncryptHandshakeInit::<CryptoCore>::new(
            HandshakeState::default(),
            &local.public_key,
            &peer,
            &EphemeralPrivateKey::generate(&mut rng()),
            Tai64N::now(),
            rng().random(),
            None,
        )
        .unwrap();
        let secret =
            SharedSecret::new(CryptoCore::x25519(&local.private_key, &request.peer_key()).unwrap())
                .unwrap();
        let (init, _) = request.complete(secret);

        (
            init,
            StaticInitiatorConfig::new(ssk_r),
            StaticPeerConfig::new(spk_i, Some(psk), None),
        )
    })
    .bench_local_values(|(msg, config, peer)| {
        let request = DecryptHandshakeInit::<CryptoCore>::new(
            msg,
            HandshakeState::default(),
            &config.public_key,
        );
        let secret = SharedSecret::new(
            CryptoCore::x25519(&config.private_key, &request.peer_key()).unwrap(),
        )
        .unwrap();
        let request = request.complete(secret).unwrap();
        let secret = SharedSecret::new(
            CryptoCore::x25519(&config.private_key, &request.peer_key()).unwrap(),
        )
        .unwrap();
        let decrypted = request.complete(secret).unwrap();
        assert_eq!(decrypted.static_key().0, peer.key.0);
        let (response, transcript) = decrypted
            .respond(
                &EphemeralPrivateKey::generate(&mut rng()),
                &peer,
                rng().random(),
                None,
            )
            .unwrap();
        drop(transcript);
        response
    })
}
