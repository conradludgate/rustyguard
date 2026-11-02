//! Statically selected implementations of WireGuard's fixed crypto suite.

#[cfg(any(feature = "graviola", feature = "rustcrypto"))]
use crate::{CryptoError, CryptoPrimatives, Key, PublicKey, StaticPrivateKey};

/// The default desktop provider, backed by Graviola.
#[cfg(feature = "graviola")]
pub struct Graviola;

#[cfg(feature = "graviola")]
impl CryptoPrimatives for Graviola {
    fn x25519(secret: &StaticPrivateKey, public: &PublicKey) -> Result<Key, CryptoError> {
        use graviola::key_agreement::x25519::PublicKey;
        use graviola::key_agreement::x25519::StaticPrivateKey;

        StaticPrivateKey::from_array(&secret.0)
            .diffie_hellman(&PublicKey::from_array(&public.0))
            .map(|s| s.0)
            .map_err(|_| CryptoError::KeyExchangeError)
    }

    fn x25519_pubkey(secret: &StaticPrivateKey) -> PublicKey {
        use graviola::key_agreement::x25519::StaticPrivateKey;

        PublicKey(
            StaticPrivateKey::from_array(&secret.0)
                .public_key()
                .as_bytes(),
        )
    }

    fn chacha20poly1305_enc(
        key: &Key,
        nonce: &[u8; 12],
        aad: &[u8],
        payload: &mut [u8],
        tag: &mut [u8; 16],
    ) {
        use graviola::aead::ChaCha20Poly1305;
        ChaCha20Poly1305::new(*key).encrypt(nonce, aad, payload, tag);
    }

    fn chacha20poly1305_dec(
        key: &Key,
        nonce: &[u8; 12],
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        use graviola::aead::ChaCha20Poly1305;
        ChaCha20Poly1305::new(*key)
            .decrypt(nonce, aad, payload, tag)
            .map_err(|_| CryptoError::DecryptionError)
    }
    fn xchacha20poly1305_enc(
        key: &Key,
        nonce: &[u8; 24],
        aad: &[u8],
        payload: &mut [u8],
        tag: &mut [u8; 16],
    ) {
        use graviola::aead::XChaCha20Poly1305;
        XChaCha20Poly1305::new(*key).encrypt(nonce, aad, payload, tag);
    }

    fn xchacha20poly1305_dec(
        key: &Key,
        nonce: &[u8; 24],
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        use graviola::aead::XChaCha20Poly1305;
        XChaCha20Poly1305::new(*key)
            .decrypt(nonce, aad, payload, tag)
            .map_err(|_| CryptoError::DecryptionError)
    }
}

/// Portable RustCrypto X25519 and AEAD, with the shared no_std BLAKE2s helpers.
#[cfg(feature = "rustcrypto")]
pub struct RustCrypto;

#[cfg(feature = "rustcrypto")]
impl CryptoPrimatives for RustCrypto {
    fn x25519(secret: &StaticPrivateKey, public: &PublicKey) -> Result<Key, CryptoError> {
        let secret = x25519_dalek::StaticSecret::from(secret.0);
        let public = x25519_dalek::PublicKey::from(public.0);
        let shared = secret.diffie_hellman(&public);
        if !shared.was_contributory() {
            return Err(CryptoError::KeyExchangeError);
        }
        Ok(shared.to_bytes())
    }

    fn x25519_pubkey(secret: &StaticPrivateKey) -> PublicKey {
        let secret = x25519_dalek::StaticSecret::from(secret.0);
        PublicKey(x25519_dalek::PublicKey::from(&secret).to_bytes())
    }

    fn chacha20poly1305_enc(
        key: &Key,
        nonce: &[u8; 12],
        aad: &[u8],
        payload: &mut [u8],
        tag: &mut [u8; 16],
    ) {
        use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit};
        *tag = ChaCha20Poly1305::new(key.into())
            .encrypt_in_place_detached(nonce.into(), aad, payload)
            .expect("payload exceeds the ChaCha20-Poly1305 message limit")
            .into();
    }

    fn chacha20poly1305_dec(
        key: &Key,
        nonce: &[u8; 12],
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit};
        ChaCha20Poly1305::new(key.into())
            .decrypt_in_place_detached(nonce.into(), aad, payload, tag.into())
            .map_err(|_| CryptoError::DecryptionError)
    }

    fn xchacha20poly1305_enc(
        key: &Key,
        nonce: &[u8; 24],
        aad: &[u8],
        payload: &mut [u8],
        tag: &mut [u8; 16],
    ) {
        use chacha20poly1305::{aead::AeadInPlace, KeyInit, XChaCha20Poly1305};
        *tag = XChaCha20Poly1305::new(key.into())
            .encrypt_in_place_detached(nonce.into(), aad, payload)
            .expect("payload exceeds the XChaCha20-Poly1305 message limit")
            .into();
    }

    fn xchacha20poly1305_dec(
        key: &Key,
        nonce: &[u8; 24],
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        use chacha20poly1305::{aead::AeadInPlace, KeyInit, XChaCha20Poly1305};
        XChaCha20Poly1305::new(key.into())
            .decrypt_in_place_detached(nonce.into(), aad, payload, tag.into())
            .map_err(|_| CryptoError::DecryptionError)
    }
}
