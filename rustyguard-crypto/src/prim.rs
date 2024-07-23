pub use chacha20poly1305::Key;
use rustyguard_types::EncryptedEmpty;
use rustyguard_types::EncryptedPublicKey;
use rustyguard_types::EncryptedTimestamp;
use rustyguard_types::Tag;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;
use zerocopy::AsBytes;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use crate::AntiReplay;
use crate::CryptoError;

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
    use blake2::digest::Digest;
    let mut mac = blake2::Blake2s256::default();
    for msg in msg {
        mac.update(msg);
    }
    mac.finalize().into()
}

pub fn mac(key: &[u8], msg: &[u8]) -> Mac {
    use blake2::digest::Mac;
    let mut mac = blake2::Blake2sMac::<blake2::digest::consts::U16>::new_from_slice(key).unwrap();
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

fn hmac<const M: usize>(key: &Key, msg: [&[u8]; M]) -> Key {
    use hmac::Mac;
    type Hmac = hmac::SimpleHmac<blake2::Blake2s256>;

    let mut hmac = Hmac::new_from_slice(key).unwrap();
    for msg in msg {
        hmac.update(msg);
    }
    hmac.finalize().into_bytes()
}

fn hkdf<const N: usize>(key: &Key, msg: &[u8]) -> [Key; N] {
    use hmac::Mac;
    type Hmac = hmac::SimpleHmac<blake2::Blake2s256>;

    assert!(N <= 255);

    let mut output = [Key::default(); N];

    if N == 0 {
        return output;
    }

    let hmac = Hmac::new_from_slice(&hmac(key, [msg])).unwrap();
    let mut ti = hmac.clone().chain_update([1u8]).finalize().into_bytes();
    output[0] = ti;

    for i in 1..N as u8 {
        ti = hmac
            .clone()
            .chain_update(ti)
            .chain_update([i + 1])
            .finalize()
            .into_bytes();
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
    pub fn mix_chain(&mut self, b: &[u8]) {
        let [c] = hkdf(&self.chain, b);
        self.chain = c;
    }

    pub fn mix_dh(&mut self, sk: &StaticSecret, pk: &PublicKey) {
        let prk = sk.diffie_hellman(pk);
        let [c] = hkdf(&self.chain, prk.as_bytes());
        self.chain = c;
    }

    pub fn mix_key_dh(&mut self, sk: &StaticSecret, pk: &PublicKey) -> Key {
        self.mix_key(sk.diffie_hellman(pk).as_bytes())
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

#[derive(ZeroizeOnDrop)]
pub struct EncryptionKey {
    key: chacha20poly1305::ChaCha20Poly1305,
    pub counter: u64,
}

impl EncryptionKey {
    pub fn new(key: chacha20poly1305::Key) -> Self {
        use chacha20poly1305::KeyInit;
        Self {
            key: chacha20poly1305::ChaCha20Poly1305::new(&key),
            counter: 0,
        }
    }

    pub fn encrypt(&mut self, payload: &mut [u8]) -> Tag {
        use chacha20poly1305::{AeadInPlace, Nonce};
        let n = self.counter;
        self.counter += 1;

        let mut nonce = Nonce::default();
        nonce[4..12].copy_from_slice(&n.to_le_bytes());

        let tag = self
            .key
            .encrypt_in_place_detached(&nonce, &[], payload)
            .expect("message to large to encrypt");

        Tag(tag.into())
    }
}

#[derive(ZeroizeOnDrop)]
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

    pub fn decrypt(
        &mut self,
        counter: u64,
        payload: &mut [u8],
        tag: Tag,
    ) -> Result<(), CryptoError> {
        use chacha20poly1305::{AeadInPlace, Nonce};

        if !self.replay.check(counter) {
            unsafe_log!("payload replayed or is too old");
            return Err(CryptoError::Rejected);
        }

        let mut nonce = Nonce::default();
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());

        self.key
            .decrypt_in_place_detached(
                &nonce,
                &[],
                payload,
                chacha20poly1305::Tag::from_slice(&tag.0),
            )
            .map_err(|_| CryptoError::DecryptionError)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use blake2::Digest;
    use chacha20poly1305::Key;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    #[test]
    fn construction_identifier() {
        let c = blake2::Blake2s256::default()
            .chain_update(b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
            .finalize();
        let h = blake2::Blake2s256::default()
            .chain_update(c)
            .chain_update(b"WireGuard v1 zx2c4 Jason@zx2c4.com")
            .finalize();

        assert_eq!(&*c, &super::CONSTRUCTION_HASH);
        assert_eq!(&*h, &super::IDENTIFIER_HASH);
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
