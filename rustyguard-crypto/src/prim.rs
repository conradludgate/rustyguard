use core::array;

use graviola::aead::ChaCha20Poly1305;
use rustyguard_types::EncryptedEmpty;
use rustyguard_types::EncryptedPublicKey;
use rustyguard_types::EncryptedTimestamp;
use rustyguard_types::Tag;
use zerocopy::IntoBytes;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use crate::CryptoError;
use crate::EphemeralPrivateKey;
use rustyguard_utils::anti_replay::AntiReplay;

pub type Key = [u8; 32];

/// Construction: The UTF-8 string literal “Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s”, 37 bytes of output.
/// Identifier: The UTF-8 string literal “WireGuard v1 zx2c4 Jason@zx2c4.com”, 34 bytes of output.
/// Ci := Hash(Construction)
/// Hi := Hash(Ci || Identifier)
pub(crate) const CONSTRUCTION_HASH: [u8; 32] = [
    96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235, 66, 6, 248,
    114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
];
pub(crate) const IDENTIFIER_HASH: [u8; 32] = [
    34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108, 102, 34,
    147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
];
pub(crate) const LABEL_MAC1: [u8; 8] = *b"mac1----";
pub(crate) const LABEL_COOKIE: [u8; 8] = *b"cookie--";

fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0; 12];
    n[4..].copy_from_slice(&u64::to_le_bytes(counter));
    n
}

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

fn get_der_key(key: &Key) -> [u8; 64] {
    let mut der_key = [0u8; 64];
    der_key[..key.len()].copy_from_slice(key);
    der_key
}

fn get_pad(key: &Key) -> ([u8; 64], [u8; 64]) {
    let der_key = get_der_key(key);
    let mut ipad_key = der_key;
    for b in ipad_key.iter_mut() {
        *b ^= IPAD;
    }

    let mut opad_key = der_key;
    for b in opad_key.iter_mut() {
        *b ^= OPAD;
    }
    (ipad_key, opad_key)
}

fn hmac_inner<const M: usize>(ipad_key: &[u8; 64], opad_key: &[u8; 64], msg: [&[u8]; M]) -> Key {
    let mut digest = blake2s_simd::State::new();
    digest.update(ipad_key);
    for msg in msg {
        digest.update(msg);
    }

    let mut h = blake2s_simd::State::new();
    h.update(opad_key);
    h.update(digest.finalize().as_bytes());
    *h.finalize().as_array()
}

pub trait CryptoPrimatives {
    fn blake2s_hash(left: &[u8], right: &[u8]) -> Key;
    fn blake2s_mac(key: &[u8], msg: &[u8]) -> Mac;
    fn hmac_blake2s(key: &Key, msg: &[u8]) -> Key;
    fn hkdf_blake2s<const N: usize>(key: &mut Key, msg: &[u8], output: &mut [Key; N]);
    fn x25519(secret: &StaticPrivateKey, public: &PublicKey) -> Result<Key, CryptoError>;
    fn x25519_pubkey(secret: &StaticPrivateKey) -> PublicKey;
}

pub struct Core;

impl CryptoPrimatives for Core {
    fn blake2s_hash(left: &[u8], right: &[u8]) -> Key {
        let mut mac = blake2s_simd::State::new();
        mac.update(left);
        mac.update(right);
        *mac.finalize().as_array()
    }

    fn blake2s_mac(key: &[u8], msg: &[u8]) -> Mac {
        blake2s_simd::Params::new()
            .hash_length(16)
            .key(key)
            .hash(msg)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn hmac_blake2s(key: &Key, msg: &[u8]) -> Key {
        let (ipad_key, opad_key) = get_pad(key);
        hmac_inner(&ipad_key, &opad_key, [msg])
    }

    /// Performs the operation
    ///
    /// ```ignore
    /// let tmp_output = HKDF_BLAKE2S(key, msg, N+1);
    /// *key = tmp_output[0];
    /// output.copy_from_slice(&tmp_output[1..]);
    /// ```
    fn hkdf_blake2s<const N: usize>(key: &mut Key, msg: &[u8], output: &mut [Key; N]) {
        assert!(N < 255);

        let (ipad_key, opad_key) = get_pad(&Self::hmac_blake2s(key, msg));

        let mut ti = hmac_inner(&ipad_key, &opad_key, [&[1u8]]);
        *key = ti;

        for i in 0..N as u8 {
            ti = hmac_inner(&ipad_key, &opad_key, [&ti[..], &[i + 2]]);
            output[i as usize] = ti;
        }
    }

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
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HandshakeState {
    hash: [u8; 32],
    chain: Key,
}

impl Default for HandshakeState {
    fn default() -> Self {
        let chain = Key::from(CONSTRUCTION_HASH);
        let hash = IDENTIFIER_HASH;
        Self { chain, hash }
    }
}

impl HandshakeState {
    /// Like mix-key, but discards the unused key
    pub fn mix_chain<C: CryptoPrimatives>(&mut self, b: &[u8]) {
        C::hkdf_blake2s(&mut self.chain, b, &mut []);
    }

    pub fn mix_dh<C: CryptoPrimatives>(
        &mut self,
        sk: &StaticPrivateKey,
        pk: &PublicKey,
    ) -> Result<(), CryptoError> {
        let shared_secret = C::x25519(sk, pk)?;
        C::hkdf_blake2s(&mut self.chain, &shared_secret, &mut []);
        Ok(())
    }

    pub fn mix_key_dh<C: CryptoPrimatives>(
        &mut self,
        sk: &StaticPrivateKey,
        pk: &PublicKey,
    ) -> Result<Key, CryptoError> {
        let shared_secret = C::x25519(sk, pk)?;
        Ok(self.mix_key::<C>(&shared_secret))
    }

    pub fn mix_edh<C: CryptoPrimatives>(
        &mut self,
        sk: &EphemeralPrivateKey,
        pk: &PublicKey,
    ) -> Result<(), CryptoError> {
        self.mix_dh::<C>(&sk.0, pk)
    }

    pub fn mix_key_edh<C: CryptoPrimatives>(
        &mut self,
        sk: &EphemeralPrivateKey,
        pk: &PublicKey,
    ) -> Result<Key, CryptoError> {
        self.mix_key_dh::<C>(&sk.0, pk)
    }

    fn mix_key<C: CryptoPrimatives>(&mut self, b: &[u8]) -> Key {
        let mut k = Key::default();
        C::hkdf_blake2s(&mut self.chain, b, array::from_mut(&mut k));
        k
    }

    pub fn mix_key_and_hash<C: CryptoPrimatives>(&mut self, b: &[u8]) -> Key {
        let mut tk = [Key::default(); 2];
        C::hkdf_blake2s(&mut self.chain, b, &mut tk);
        self.mix_hash::<C>(&tk[0]);
        tk[1]
    }

    pub fn mix_hash<C: CryptoPrimatives>(&mut self, b: &[u8]) {
        self.hash = C::blake2s_hash(&self.hash, b);
    }

    pub fn split<C: CryptoPrimatives>(
        &mut self,
        initiator: bool,
    ) -> (EncryptionKey, DecryptionKey) {
        let mut k2 = Key::default();
        C::hkdf_blake2s(&mut self.chain, &[], array::from_mut(&mut k2));
        let k1 = self.chain;
        self.zeroize();

        if initiator {
            (EncryptionKey::new(k1), DecryptionKey::new(k2))
        } else {
            (EncryptionKey::new(k2), DecryptionKey::new(k1))
        }
    }
}

pub trait Encrypted<const N: usize> {
    fn decrypt_and_hash<C: CryptoPrimatives>(
        &mut self,
        state: &mut HandshakeState,
        key: &Key,
    ) -> Result<&mut [u8; N], CryptoError>;

    fn encrypt_and_hash<C: CryptoPrimatives>(
        msg: [u8; N],
        state: &mut HandshakeState,
        key: &Key,
    ) -> Self;
}

macro_rules! encrypted {
    ($i:ident, $n:literal) => {
        impl Encrypted<$n> for $i {
            fn decrypt_and_hash<C: CryptoPrimatives>(
                &mut self,
                state: &mut HandshakeState,
                key: &Key,
            ) -> Result<&mut [u8; $n], CryptoError> {
                let key = ChaCha20Poly1305::new(*key);

                let aad = state.hash;
                state.mix_hash::<C>(self.as_bytes());

                key.decrypt(&nonce(0), &aad, &mut self.msg, &self.tag.0)
                    .map_err(|_| CryptoError::DecryptionError)?;

                Ok(&mut self.msg)
            }

            fn encrypt_and_hash<C: CryptoPrimatives>(
                msg: [u8; $n],
                state: &mut HandshakeState,
                key: &Key,
            ) -> Self {
                let key = ChaCha20Poly1305::new(*key);

                let aad = state.hash;

                let mut out = Self {
                    msg,
                    tag: Tag([0; 16]),
                };

                key.encrypt(&nonce(0), &aad, &mut out.msg, &mut out.tag.0);

                state.mix_hash::<C>(out.as_bytes());

                out
            }
        }
    };
}

encrypted!(EncryptedEmpty, 0);
encrypted!(EncryptedTimestamp, 12);
encrypted!(EncryptedPublicKey, 32);

pub type Mac = [u8; 16];
pub struct StaticPrivateKey(pub [u8; 32]);
pub struct PublicKey(pub [u8; 32]);

pub struct EncryptionKey {
    key: ChaCha20Poly1305,
    counter: u64,
}

impl EncryptionKey {
    pub fn new(key: Key) -> Self {
        Self {
            key: ChaCha20Poly1305::new(key),
            counter: 0,
        }
    }

    pub fn encrypt(&mut self, payload: &mut [u8]) -> Tag {
        let n = self.counter;
        self.counter += 1;
        let nonce = nonce(n);
        let mut tag = [0; 16];
        self.key.encrypt(&nonce, &[], payload, &mut tag);

        Tag(tag)
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }
}

pub struct DecryptionKey {
    key: ChaCha20Poly1305,
    replay: AntiReplay,
}

impl DecryptionKey {
    pub fn new(key: Key) -> Self {
        Self {
            key: ChaCha20Poly1305::new(key),
            replay: AntiReplay::default(),
        }
    }

    pub fn decrypt<'b>(
        &mut self,
        counter: u64,
        payload_and_tag: &'b mut [u8],
    ) -> Result<&'b mut [u8], CryptoError> {
        if !self.replay.check(counter) {
            unsafe_log!("payload replayed or is too old");
            return Err(CryptoError::Rejected);
        }

        let nonce = nonce(counter);

        let pos = payload_and_tag.len() - 16;
        let (payload, tag) = payload_and_tag.split_at_mut(pos);

        self.key
            .decrypt(&nonce, &[], payload, tag)
            .map_err(|_| CryptoError::DecryptionError)?;

        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use crate::{
        prim::{CryptoPrimatives, Key},
        CryptoCore,
    };

    #[test]
    fn construction_identifier() {
        let c = blake2s_simd::State::new()
            .update(b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
            .finalize();
        let h = blake2s_simd::State::new()
            .update(c.as_bytes())
            .update(b"WireGuard v1 zx2c4 Jason@zx2c4.com")
            .finalize();

        assert_eq!(c.as_array(), &super::CONSTRUCTION_HASH);
        assert_eq!(h.as_array(), &super::IDENTIFIER_HASH);
    }

    #[test]
    fn hkdf_snapshot() {
        let mut rng = StdRng::seed_from_u64(2);
        let mut key = Key::default();
        rng.fill_bytes(&mut key);

        let mut bc = [Key::default(); 2];
        CryptoCore::hkdf_blake2s(&mut key, b"msg data here even more data", &mut bc);

        let a = key;
        let [b, c] = bc;
        insta::assert_debug_snapshot!([a, b, c]);
    }

    #[test]
    fn hash_snapshot() {
        let h = CryptoCore::blake2s_hash(b"msg data here", b" even more data");
        insta::assert_debug_snapshot!(h);
    }

    #[test]
    fn mac_snapshot() {
        let mut rng = StdRng::seed_from_u64(2);
        let mut key = Key::default();
        rng.fill_bytes(&mut key);
        let h = CryptoCore::blake2s_mac(&key, b"msg data here even more data");
        insta::assert_debug_snapshot!(h);
    }
}
