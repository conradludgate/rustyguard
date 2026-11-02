#![cfg(any(feature = "graviola", feature = "rustcrypto"))]

use rand::{rngs::StdRng, SeedableRng};
use rustyguard_crypto::{
    CryptoCore, CryptoError, CryptoPrimatives, DecryptHandshakeInit, DecryptHandshakeResp,
    EncryptHandshakeInit, EphemeralPrivateKey, HandshakeState, PublicKey, SharedSecret,
    StaticPeerConfig, StaticPrivateKey,
};
use std::rc::Rc;
use tai64::{Tai64, Tai64N};

// Caller-owned, deliberately !Send, and genuinely suspends before doing DH.
async fn agree(key: Rc<StaticPrivateKey>, peer: PublicKey) -> Result<SharedSecret, CryptoError> {
    tokio::task::yield_now().await;
    SharedSecret::new(CryptoCore::x25519(&key, &peer)?)
}

#[tokio::test(flavor = "current_thread")]
async fn async_keys_complete_handshake_and_exchange_data() -> Result<(), CryptoError> {
    let initiator = Rc::new(StaticPrivateKey([1; 32]));
    let responder = Rc::new(StaticPrivateKey([2; 32]));
    let peer_i = StaticPeerConfig::with_crypto::<CryptoCore>(
        CryptoCore::x25519_pubkey(&initiator),
        Some([3; 32]),
        None,
    );
    let mut peer_r = StaticPeerConfig::with_crypto::<CryptoCore>(
        CryptoCore::x25519_pubkey(&responder),
        Some([3; 32]),
        None,
    );
    let mut rng = StdRng::seed_from_u64(42);
    let ephemeral_i = EphemeralPrivateKey::generate(&mut rng);
    let ephemeral_r = EphemeralPrivateKey::generate(&mut rng);
    let now = Tai64N(Tai64(1), 2);

    let request = EncryptHandshakeInit::<CryptoCore>::new(
        HandshakeState::default(),
        &peer_i.key,
        &peer_r,
        &ephemeral_i,
        now,
        1,
        None,
    )?;
    let secret = agree(initiator.clone(), request.peer_key()).await?;
    let (initiation, transcript_i) = request.complete(secret);

    let request =
        DecryptHandshakeInit::<CryptoCore>::new(initiation, HandshakeState::default(), &peer_r.key);
    let secret = agree(responder.clone(), request.peer_key()).await?;
    let request = request.complete(secret)?;
    let secret = agree(responder, request.peer_key()).await?;
    let initiation = request.complete(secret)?;
    assert_eq!(initiation.static_key().0, peer_i.key.0);
    assert_eq!(initiation.timestamp(), &now.to_bytes());
    let (response, mut transcript_r) = initiation.respond(&ephemeral_r, &peer_i, 2, None)?;

    let request =
        DecryptHandshakeResp::<CryptoCore>::new(response, &transcript_i, &peer_r, &ephemeral_i)?;
    // The pending request must retain the PSK it was prepared with.
    peer_r.preshared_key.fill(0);
    let secret = agree(initiator, request.peer_key()).await?;
    let mut transcript_i = request.complete(secret)?;

    let (mut send_i, mut recv_i) = transcript_i.split::<CryptoCore>(true);
    let (mut send_r, mut recv_r) = transcript_r.split::<CryptoCore>(false);
    for (send, recv) in [(&mut send_i, &mut recv_r), (&mut send_r, &mut recv_i)] {
        let mut frame = [0; 32];
        frame[..16].copy_from_slice(b"hello, async key");
        let tag = send.encrypt::<CryptoCore>(&mut frame[..16]);
        frame[16..].copy_from_slice(&tag.0);
        assert_eq!(
            recv.decrypt::<CryptoCore>(0, &mut frame)?,
            b"hello, async key"
        );
    }
    Ok(())
}
