use graviola::aead::ChaCha20Poly1305;
use graviola::key_agreement::x25519::PublicKey;
use graviola::key_agreement::x25519::StaticPrivateKey;
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

pub(crate) fn hash(msg: [&[u8]; 2]) -> Key {
    let mut mac = blake2s_simd::State::new();
    for msg in msg {
        mac.update(msg);
    }
    *mac.finalize().as_array()
}

pub fn mac(key: &[u8], msg: &[u8]) -> Mac {
    blake2s_simd::Params::new()
        .hash_length(16)
        .key(key)
        .hash(msg)
        .as_bytes()
        .try_into()
        .unwrap()
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

fn hmac<const M: usize>(key: &Key, msg: [&[u8]; M]) -> Key {
    let (ipad_key, opad_key) = get_pad(key);
    hmac_inner(&ipad_key, &opad_key, msg)
}

fn hkdf<const N: usize>(key: &Key, msg: &[u8]) -> [Key; N] {
    assert!(N > 0);
    assert!(N <= 255);

    let mut output = [Key::default(); N];

    let (ipad_key, opad_key) = get_pad(&hmac(key, [msg]));

    let mut ti = hmac_inner(&ipad_key, &opad_key, [&[1u8]]);
    output[0] = ti;

    for i in 1..N as u8 {
        ti = hmac_inner(&ipad_key, &opad_key, [&ti[..], &[i + 1]]);
        output[i as usize] = ti;
    }

    output
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
    pub fn mix_chain(&mut self, b: &[u8]) {
        let [c] = hkdf(&self.chain, b);
        self.chain = c;
    }

    pub fn mix_dh(&mut self, sk: &StaticPrivateKey, pk: &PublicKey) -> Result<(), CryptoError> {
        let shared_secret = sk
            .diffie_hellman(pk)
            .map_err(|_| CryptoError::KeyExchangeError)?;
        let [c] = hkdf(&self.chain, &shared_secret.0);
        self.chain = c;
        Ok(())
    }

    pub fn mix_key_dh(
        &mut self,
        sk: &StaticPrivateKey,
        pk: &PublicKey,
    ) -> Result<Key, CryptoError> {
        let shared_secret = sk
            .diffie_hellman(pk)
            .map_err(|_| CryptoError::KeyExchangeError)?;
        Ok(self.mix_key(&shared_secret.0))
    }

    pub fn mix_edh(&mut self, sk: &EphemeralPrivateKey, pk: &PublicKey) -> Result<(), CryptoError> {
        self.mix_dh(&sk.0, pk)
    }

    pub fn mix_key_edh(
        &mut self,
        sk: &EphemeralPrivateKey,
        pk: &PublicKey,
    ) -> Result<Key, CryptoError> {
        self.mix_key_dh(&sk.0, pk)
    }

    fn mix_key(&mut self, b: &[u8]) -> Key {
        let [c, k] = hkdf(&self.chain, b);
        self.chain = c;
        k
    }

    pub fn mix_key_and_hash(&mut self, b: &[u8]) -> Key {
        let [c, t, k] = hkdf(&self.chain, b);
        self.chain = c;
        self.mix_hash(&t[..]);
        k
    }

    pub fn mix_hash(&mut self, b: &[u8]) {
        self.hash = hash([&self.hash, b]);
    }

    pub fn split(&mut self, initiator: bool) -> (EncryptionKey, DecryptionKey) {
        let [k1, k2] = hkdf(&self.chain, &[]);
        self.zeroize();

        if initiator {
            (EncryptionKey::new(k1), DecryptionKey::new(k2))
        } else {
            (EncryptionKey::new(k2), DecryptionKey::new(k1))
        }
    }
}

pub trait Encrypted<const N: usize> {
    fn decrypt_and_hash(
        &mut self,
        state: &mut HandshakeState,
        key: &Key,
    ) -> Result<&mut [u8; N], CryptoError>;

    fn encrypt_and_hash(msg: [u8; N], state: &mut HandshakeState, key: &Key) -> Self;
}

macro_rules! encrypted {
    ($i:ident, $n:literal) => {
        impl Encrypted<$n> for $i {
            fn decrypt_and_hash(
                &mut self,
                state: &mut HandshakeState,
                key: &Key,
            ) -> Result<&mut [u8; $n], CryptoError> {
                let key = ChaCha20Poly1305::new(*key);

                let aad = state.hash;
                state.mix_hash(self.as_bytes());

                key.decrypt(&nonce(0), &aad, &mut self.msg, &self.tag.0)
                    .map_err(|_| CryptoError::DecryptionError)?;

                Ok(&mut self.msg)
            }

            fn encrypt_and_hash(msg: [u8; $n], state: &mut HandshakeState, key: &Key) -> Self {
                let key = ChaCha20Poly1305::new(*key);

                let aad = state.hash;

                let mut out = Self {
                    msg,
                    tag: Tag([0; 16]),
                };

                key.encrypt(&nonce(0), &aad, &mut out.msg, &mut out.tag.0);

                state.mix_hash(out.as_bytes());

                out
            }
        }
    };
}

encrypted!(EncryptedEmpty, 0);
encrypted!(EncryptedTimestamp, 12);
encrypted!(EncryptedPublicKey, 32);

pub type Mac = [u8; 16];

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

    use crate::prim::Key;

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
        let [a, b, c] = super::hkdf(&key, b"msg data here even more data");
        insta::assert_debug_snapshot!([a, b, c]);
    }

    #[test]
    fn hash_snapshot() {
        let h = super::hash([b"msg data here", b" even more data"]);
        insta::assert_debug_snapshot!(h);
    }

    #[test]
    fn mac_snapshot() {
        let mut rng = StdRng::seed_from_u64(2);
        let mut key = Key::default();
        rng.fill_bytes(&mut key);
        let h = super::mac(&key, b"msg data here even more data");
        insta::assert_debug_snapshot!(h);
    }
}
