use blake2::digest::consts::U32;
use blake2::digest::generic_array::ArrayLength;
use blake2::digest::generic_array::GenericArray;
use blake2::digest::{Digest, Output};
use blake2::Blake2s256;
use bytemuck::bytes_of;
use bytemuck::{Pod, TransparentWrapper, Zeroable};
use chacha20poly1305::consts::U16;
use chacha20poly1305::Key;
use chacha20poly1305::Nonce;
use chacha20poly1305::XNonce;
use hmac::SimpleHmac;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

pub(crate) fn nonce(counter: u64) -> Nonce {
    let mut n = Nonce::default();
    n[4..].copy_from_slice(&u64::to_le_bytes(counter));
    n
}

pub(crate) fn hash<const M: usize>(msg: [&[u8]; M]) -> Output<Blake2s256> {
    let mut digest = Blake2s256::default();
    for msg in msg {
        digest.update(msg);
    }
    digest.finalize()
}

pub(crate) fn mac<const M: usize>(key: &[u8], msg: [&[u8]; M]) -> GenericArray<u8, U16> {
    use blake2::digest::Mac;
    let mut mac = blake2::Blake2sMac::<U16>::new_from_slice(key).unwrap();
    for msg in msg {
        mac.update(msg);
    }
    mac.finalize().into_bytes()
}

fn hmac<const M: usize>(key: &GenericArray<u8, U32>, msg: [&[u8]; M]) -> Output<Blake2s256> {
    use hmac::Mac;
    let mut hmac = <SimpleHmac<Blake2s256> as Mac>::new_from_slice(key).unwrap();
    for msg in msg {
        hmac.update(msg);
    }
    hmac.finalize().into_bytes()
}

pub(crate) fn hkdf<const N: usize, const M: usize>(
    key: &GenericArray<u8, U32>,
    msg: [&[u8]; M],
) -> [Output<Blake2s256>; N] {
    assert!(N <= 255);

    let mut output = [Output::<Blake2s256>::default(); N];

    if N == 0 {
        return output;
    }

    let t0 = hmac(key, msg);
    let mut ti = hmac(&t0, [&[1]]);
    output[0] = ti;
    for i in 1..N as u8 {
        ti = hmac(&t0, [&ti, &[i + 1]]);
        output[i as usize] = ti;
    }

    output
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HandshakeState {
    hash: GenericArray<u8, U32>,
    chain: GenericArray<u8, U32>,
}

impl Default for HandshakeState {
    fn default() -> Self {
        let chain = GenericArray::from(crate::CONSTRUCTION_HASH);
        let hash = GenericArray::from(crate::IDENTIFIER_HASH);
        Self { chain, hash }
    }
}

impl HandshakeState {
    pub fn mix_chain(&mut self, b: &[u8]) {
        let [c] = hkdf(&self.chain, [b]);
        self.chain = c;
    }

    pub fn mix_dh(&mut self, sk: &StaticSecret, pk: &PublicKey) {
        let prk = sk.diffie_hellman(pk);
        let [c] = hkdf(&self.chain, [prk.as_bytes()]);
        self.chain = c;
    }

    pub fn mix_key_dh(&mut self, sk: &StaticSecret, pk: &PublicKey) -> Key {
        let prk = sk.diffie_hellman(pk);
        let [c, k] = hkdf(&self.chain, [prk.as_bytes()]);
        self.chain = c;
        k
    }

    pub fn mix_key2(&mut self, b: &[u8]) -> Key {
        let [c, t, k] = hkdf(&self.chain, [b]);
        self.chain = c;
        self.mix_hash(&t);
        k
    }

    pub fn mix_hash(&mut self, b: &[u8]) {
        self.hash = hash([&self.hash, b]);
    }

    pub fn split(&mut self) -> (Key, Key) {
        let [k1, k2] = hkdf(&self.chain, []);
        self.zeroize();
        (k1, k2)
    }
}

#[derive(Clone, TransparentWrapper)]
#[repr(transparent)]
pub(crate) struct Bytes<U: ArrayLength<u8>>(pub GenericArray<u8, U>);
impl<U: ArrayLength<u8>> Copy for Bytes<U> where GenericArray<u8, U>: Copy {}

// SAFETY: bytes are plain-old-data
unsafe impl<U: ArrayLength<u8>> Pod for Bytes<U> where GenericArray<u8, U>: Copy {}
// SAFETY: bytes are zeroable
unsafe impl<U: ArrayLength<u8>> Zeroable for Bytes<U> {}

// pub(crate) type Encrypted<U> = <U as Add<U16>>::Output;

#[derive(Clone, Copy, Pod, Zeroable, TransparentWrapper)]
#[repr(transparent)]
pub struct Cookie(pub(crate) [u8; 16]);

#[derive(Clone, Copy, Pod, Zeroable, TransparentWrapper)]
#[repr(transparent)]
pub struct Tag([u8; 16]);

impl Tag {
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

encrypted!(Encrypted0, 0);
encrypted!(Encrypted12, 12);
encrypted!(Encrypted32, 32);

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
        nonce: &XNonce,
        aad: &[u8],
    ) -> Result<&mut Cookie, crate::Error> {
        use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};

        XChaCha20Poly1305::new(key)
            .decrypt_in_place_detached(nonce, aad, &mut self.msg.0, self.tag.as_tag())
            .map_err(|_| crate::Error::Unspecified)?;

        Ok(&mut self.msg)
    }

    pub(crate) fn encrypt_cookie(
        mut cookie: Cookie,
        key: &Key,
        nonce: &XNonce,
        aad: &[u8],
    ) -> Self {
        use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};

        let tag = XChaCha20Poly1305::new(key)
            .encrypt_in_place_detached(nonce, aad, &mut cookie.0)
            .expect("cookie message should not be larger than max message size");

        Self {
            msg: cookie,
            tag: Tag::from_tag(tag),
        }
    }
}

#[derive(Pod, Zeroable, Clone, Copy, Default)]
#[repr(C)]
pub(crate) struct LEU32(u32);

impl LEU32 {
    pub(crate) fn get(self) -> u32 {
        u32::from_le(self.0)
    }
    pub(crate) fn new(n: u32) -> Self {
        Self(n.to_le())
    }
}

#[derive(Pod, Zeroable, Clone, Copy, Default)]
#[repr(C)]
pub(crate) struct LEU64(u64);

impl LEU64 {
    pub(crate) fn get(self) -> u64 {
        u64::from_le(self.0)
    }
    pub(crate) fn new(n: u64) -> Self {
        Self(n.to_le())
    }
}
