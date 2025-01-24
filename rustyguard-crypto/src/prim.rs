use blake2::digest::generic_array::GenericArray;
pub use chacha20poly1305::Key;
use rustyguard_types::EncryptedEmpty;
use rustyguard_types::EncryptedPublicKey;
use rustyguard_types::EncryptedTimestamp;
use rustyguard_types::Tag;
use x25519_dalek::PublicKey;
use x25519_dalek::ReusableSecret;
use x25519_dalek::StaticSecret;
use zerocopy::IntoBytes;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use crate::CryptoError;
use rustyguard_utils::anti_replay::AntiReplay;

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

fn nonce(counter: u64) -> chacha20poly1305::Nonce {
    let mut n = chacha20poly1305::Nonce::default();
    n[4..].copy_from_slice(&u64::to_le_bytes(counter));
    n
}

pub(crate) fn hash(msg: [&[u8]; 2]) -> [u8; 32] {
    use blake2::Digest;

    let mut mac = blake2::Blake2s256::new();
    for msg in msg {
        mac.update(msg);
    }
    mac.finalize().into()
}

pub fn mac(key: &[u8], msg: &[u8]) -> Mac {
    use blake2::digest::Mac;

    blake2::Blake2sMac::new(GenericArray::from_slice(key))
        .chain_update(msg)
        .finalize()
        .into_bytes()
        .into()
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
    use blake2::Digest;

    let mut digest = blake2::Blake2s256::new();
    digest.update(ipad_key);
    for msg in msg {
        digest.update(msg);
    }

    let mut h = blake2::Blake2s256::new();
    h.update(opad_key);
    h.update(digest.finalize().as_bytes());
    h.finalize()
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

fn agree<K>(sk: &StaticSecret, pk: &PublicKey, kdf: impl FnOnce(&[u8]) -> K) -> K {
    let prk = sk.diffie_hellman(pk);
    kdf(prk.as_bytes())
}

fn agree_ephemeral<K>(sk: &ReusableSecret, pk: &PublicKey, kdf: impl FnOnce(&[u8]) -> K) -> K {
    let prk = sk.diffie_hellman(pk);
    kdf(prk.as_bytes())
}

impl HandshakeState {
    /// Like mix-key, but discards the unused key
    pub fn mix_chain(&mut self, b: &[u8]) {
        let [c] = hkdf(&self.chain, b);
        self.chain = c;
    }

    pub fn mix_dh(&mut self, sk: &StaticSecret, pk: &PublicKey) {
        let [c] = agree(sk, pk, |prk| hkdf(&self.chain, prk));
        self.chain = c;
    }

    pub fn mix_key_dh(&mut self, sk: &StaticSecret, pk: &PublicKey) -> Key {
        agree(sk, pk, |prk| self.mix_key(prk))
    }

    pub fn mix_edh(&mut self, sk: &ReusableSecret, pk: &PublicKey) {
        let [c] = agree_ephemeral(sk, pk, |prk| hkdf(&self.chain, prk));
        self.chain = c;
    }

    pub fn mix_key_edh(&mut self, sk: &ReusableSecret, pk: &PublicKey) -> Key {
        agree_ephemeral(sk, pk, |prk| self.mix_key(prk))
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
                use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};

                let aad = state.hash;
                state.mix_hash(self.as_bytes());

                ChaCha20Poly1305::new(key)
                    .decrypt_in_place_detached(&nonce(0), &aad, &mut self.msg, (&self.tag.0).into())
                    .map_err(|_| CryptoError::DecryptionError)?;
                Ok(&mut self.msg)
            }

            fn encrypt_and_hash(mut msg: [u8; $n], state: &mut HandshakeState, key: &Key) -> Self {
                use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};

                let aad = state.hash;
                let tag = ChaCha20Poly1305::new(key)
                    .encrypt_in_place_detached(&nonce(0), &aad, &mut msg)
                    .expect("message should not be larger than max message size");

                let out = Self {
                    msg,
                    tag: Tag(tag.into()),
                };
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
    key: chacha20poly1305::ChaCha20Poly1305,
    counter: u64,
}

impl EncryptionKey {
    pub fn new(key: Key) -> Self {
        use chacha20poly1305::KeyInit;
        Self {
            key: chacha20poly1305::ChaCha20Poly1305::new(&key),
            counter: 0,
        }
    }

    pub fn encrypt(&mut self, payload: &mut [u8]) -> Tag {
        use chacha20poly1305::AeadInPlace;
        let nonce = nonce(self.counter);
        self.counter += 1;

        let tag = self
            .key
            .encrypt_in_place_detached(&nonce, &[], payload)
            .expect("message to large to encrypt");

        Tag(tag.into())
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }
}

pub struct DecryptionKey {
    key: chacha20poly1305::ChaCha20Poly1305,
    replay: AntiReplay,
}

impl DecryptionKey {
    pub fn new(key: Key) -> Self {
        use chacha20poly1305::KeyInit;
        Self {
            key: chacha20poly1305::ChaCha20Poly1305::new(&key),
            replay: AntiReplay::default(),
        }
    }

    pub fn decrypt<'b>(
        &mut self,
        counter: u64,
        payload_and_tag: &'b mut [u8],
    ) -> Result<&'b mut [u8], CryptoError> {
        use chacha20poly1305::AeadInPlace;

        if !self.replay.check(counter) {
            unsafe_log!("payload replayed or is too old");
            return Err(CryptoError::Rejected);
        }

        let mid = payload_and_tag.len() - 16;
        let (payload, tag) = payload_and_tag.split_at_mut(mid);

        let nonce = nonce(counter);

        self.key
            .decrypt_in_place_detached(&nonce, &[], payload, chacha20poly1305::Tag::from_slice(tag))
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
        use blake2::Digest;
        let c = blake2::Blake2s256::new()
            .chain_update(b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
            .finalize();
        let h = blake2::Blake2s256::new()
            .chain_update(c)
            .chain_update(b"WireGuard v1 zx2c4 Jason@zx2c4.com")
            .finalize();

        assert_eq!(<[u8; 32]>::from(c), super::CONSTRUCTION_HASH);
        assert_eq!(<[u8; 32]>::from(h), super::IDENTIFIER_HASH);
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
