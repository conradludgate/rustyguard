use bytemuck::bytes_of;
use bytemuck::{Pod, TransparentWrapper, Zeroable};
pub use chacha20poly1305::Key;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use crate::Error;

/// Construction: The UTF-8 string literal “Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s”, 37 bytes of output.
/// Identifier: The UTF-8 string literal “WireGuard v1 zx2c4 Jason@zx2c4.com”, 34 bytes of output.
/// Ci := Hash(Construction)
/// Hi := Hash(Ci || Identifier)
const CONSTRUCTION_HASH: [u8; 32] = [
    96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235, 66, 6, 248,
    114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
];
const IDENTIFIER_HASH: [u8; 32] = [
    34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108, 102, 34,
    147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
];
const LABEL_MAC1: [u8; 8] = *b"mac1----";
const LABEL_COOKIE: [u8; 8] = *b"cookie--";

fn nonce(counter: u64) -> chacha20poly1305::Nonce {
    let mut n = chacha20poly1305::Nonce::default();
    n[4..].copy_from_slice(&u64::to_le_bytes(counter));
    n
}

fn hash(msg: [&[u8]; 2]) -> [u8; 32] {
    use blake2::digest::Digest;
    let mut mac = blake2::Blake2s256::default();
    for msg in msg {
        mac.update(msg);
    }
    mac.finalize().into()
}

pub(crate) fn mac(key: &[u8], msg: &[u8]) -> Mac {
    use blake2::digest::Mac;
    let mut mac = blake2::Blake2sMac::<blake2::digest::consts::U16>::new_from_slice(key).unwrap();
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

fn hkdf<const N: usize>(key: &Key, msg: &[u8]) -> [Key; N] {
    use hmac::Mac;
    type Hmac = hmac::SimpleHmac<blake2::Blake2s256>;

    assert!(N <= 255);

    let mut output = [Key::default(); N];

    if N == 0 {
        return output;
    }

    let t0 = {
        Hmac::new_from_slice(key)
            .unwrap()
            .chain_update(msg)
            .finalize()
            .into_bytes()
    };
    let mut hmac2 = Hmac::new_from_slice(&t0).unwrap();

    let mut ti = {
        hmac2.update(&[1]);
        hmac2.finalize_reset().into_bytes()
    };
    output[0] = ti;

    for i in 1..N as u8 {
        ti = {
            hmac2.update(&ti[..]);
            hmac2.update(&[i]);
            hmac2.finalize_reset().into_bytes()
        };
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

    pub fn split(&mut self) -> (Key, Key) {
        let [k1, k2] = hkdf(&self.chain, &[]);
        self.zeroize();
        (k1, k2)
    }
}

#[derive(Clone, Copy, Pod, Zeroable, TransparentWrapper)]
#[repr(transparent)]
pub struct Cookie(pub(crate) Mac);

#[derive(Clone, Copy, Pod, Zeroable, TransparentWrapper)]
#[repr(transparent)]
pub struct Tag([u8; 16]);

impl core::ops::Deref for Tag {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Tag {
    pub(crate) fn from_slice(tag: &[u8; 16]) -> Self {
        Self(*tag)
    }

    fn as_tag(&self) -> &chacha20poly1305::Tag {
        (&self.0).into()
    }
    fn from_tag(tag: chacha20poly1305::Tag) -> Self {
        Self(tag.into())
    }
}

macro_rules! encrypted {
    ($i:ident, $n:literal) => {
        #[derive(Clone, Copy, Pod, Zeroable)]
        #[repr(C)]
        pub(crate) struct $i {
            msg: [u8; $n],
            tag: Tag,
        }

        impl $i {
            pub(crate) fn decrypt_and_hash(
                &mut self,
                state: &mut HandshakeState,
                key: &Key,
            ) -> Result<&mut [u8; $n], crate::Error> {
                use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};

                let aad = state.hash;
                state.mix_hash(bytes_of(&*self));

                ChaCha20Poly1305::new(key)
                    .decrypt_in_place_detached(&nonce(0), &aad, &mut self.msg, self.tag.as_tag())
                    .map_err(|_| crate::Error::Unspecified)?;
                Ok(&mut self.msg)
            }

            pub(crate) fn encrypt_and_hash(
                mut msg: [u8; $n],
                state: &mut HandshakeState,
                key: &Key,
            ) -> Self {
                use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};

                let aad = state.hash;
                let tag = ChaCha20Poly1305::new(key)
                    .encrypt_in_place_detached(&nonce(0), &aad, &mut msg)
                    .expect("message should not be larger than max message size");

                let out = Self {
                    msg,
                    tag: Tag::from_tag(tag),
                };
                state.mix_hash(bytes_of(&out));

                out
            }
        }
    };
}

encrypted!(EncryptedEmpty, 0);
encrypted!(EncryptedTimestamp, 12);
encrypted!(EncryptedPublicKey, 32);

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub(crate) struct EncryptedCookie {
    msg: Cookie,
    tag: Tag,
}

impl EncryptedCookie {
    pub(crate) fn decrypt_cookie(
        &mut self,
        key: &Key,
        nonce: &[u8; 24],
        aad: &[u8],
    ) -> Result<&mut Cookie, crate::Error> {
        use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};

        XChaCha20Poly1305::new(key)
            .decrypt_in_place_detached(nonce.into(), aad, &mut self.msg.0, self.tag.as_tag())
            .map_err(|_| crate::Error::Unspecified)?;

        Ok(&mut self.msg)
    }

    pub(crate) fn encrypt_cookie(
        mut cookie: Cookie,
        key: &Key,
        nonce: &[u8; 24],
        aad: &[u8],
    ) -> Self {
        use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};

        let tag = XChaCha20Poly1305::new(key)
            .encrypt_in_place_detached(nonce.into(), aad, &mut cookie.0)
            .expect("cookie message should not be larger than max message size");

        Self {
            msg: cookie,
            tag: Tag::from_tag(tag),
        }
    }
}

pub type Mac = [u8; 16];

pub fn mac1_key(spk: &PublicKey) -> Key {
    hash([&LABEL_MAC1, spk.as_bytes()]).into()
}
pub fn cookie_key(spk: &PublicKey) -> Key {
    hash([&LABEL_COOKIE, spk.as_bytes()]).into()
}

#[derive(ZeroizeOnDrop)]
pub struct EncryptionKey {
    key: chacha20poly1305::ChaCha20Poly1305,
    pub(crate) counter: u64,
}

impl EncryptionKey {
    pub(crate) fn new(key: chacha20poly1305::Key) -> Self {
        use chacha20poly1305::KeyInit;
        Self {
            key: chacha20poly1305::ChaCha20Poly1305::new(&key),
            counter: 0,
        }
    }

    pub(crate) fn encrypt(&mut self, payload: &mut [u8]) -> Tag {
        use chacha20poly1305::{AeadInPlace, Nonce};
        let n = self.counter;
        self.counter += 1;

        let mut nonce = Nonce::default();
        nonce[4..12].copy_from_slice(&n.to_le_bytes());

        let tag = self
            .key
            .encrypt_in_place_detached(&nonce, &[], payload)
            .expect("message to large to encrypt");

        Tag::from_tag(tag)
    }
}

#[derive(ZeroizeOnDrop)]
pub struct DecryptionKey {
    key: chacha20poly1305::ChaCha20Poly1305,
}
impl DecryptionKey {
    pub(crate) fn new(key: chacha20poly1305::Key) -> Self {
        use chacha20poly1305::KeyInit;
        Self {
            key: chacha20poly1305::ChaCha20Poly1305::new(&key),
        }
    }

    pub(crate) fn decrypt(
        &mut self,
        counter: u64,
        payload: &mut [u8],
        tag: Tag,
    ) -> Result<(), Error> {
        use chacha20poly1305::{AeadInPlace, Nonce};

        let mut nonce = Nonce::default();
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());

        self.key
            .decrypt_in_place_detached(
                &nonce,
                &[],
                payload,
                chacha20poly1305::Tag::from_slice(&tag.0),
            )
            .map_err(|_| Error::Rejected)?;

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
    fn hkdf() {
        let mut rng = StdRng::from_entropy();
        let mut key = Key::default();
        rng.fill_bytes(&mut key);
        let [a, b, c] = super::hkdf(&key, [b"msg data here", b" even more data"]);
        let [d, e, f] = super::hkdf(&key, [b"msg data here even more data"]);
        assert_eq!([a, b, c], [d, e, f])
    }

    #[test]
    fn hash() {
        let h1 = super::hash([b"msg data here", b" even more data"]);
        let h2 = super::hash([b"msg data here even more data"]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn mac() {
        let mut rng = StdRng::from_entropy();
        let mut key = Key::default();
        rng.fill_bytes(&mut key);
        let h1 = super::mac(&key, [b"msg data here", b" even more data"]);
        let h2 = super::mac(&key, [b"msg data here even more data"]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hkdf_snapshot() {
        let mut rng = StdRng::seed_from_u64(2);
        let mut key = Key::default();
        rng.fill_bytes(&mut key);
        let [a, b, c] = super::hkdf(&key, [b"msg data here", b" even more data"]);
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
        let h = super::mac(&key, [b"msg data here", b" even more data"]);
        insta::assert_debug_snapshot!(h);
    }
}
