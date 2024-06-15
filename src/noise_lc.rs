use aws_lc_rs::{
    aead::{self, LessSafeKey, UnboundKey},
    agreement,
};
use blake2::digest::Digest;
use cl_noise_protocol::{Cipher, Hash, U8Array, Unspecified, DH};
use zeroize::Zeroizing;

#[derive(Default)]
pub(crate) struct Blake2s(blake2::Blake2s256);

impl Hash for Blake2s {
    fn name() -> &'static str {
        "BLAKE2s"
    }

    type Block = [u8; 64];

    type Output = Sensitive;

    fn input(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn result(self) -> Self::Output {
        Sensitive(Zeroizing::new(self.0.finalize().into()))
    }
}

pub (crate) enum X25519 {}

impl DH for X25519 {
    type Key = agreement::PrivateKey;
    type Pubkey = [u8; 32];
    type Output = Sensitive;

    fn name() -> &'static str {
        "25519"
    }

    fn genkey() -> Self::Key {
        agreement::PrivateKey::generate(&agreement::X25519).unwrap()
    }

    fn pubkey(k: &Self::Key) -> Self::Pubkey {
        Self::Pubkey::from_slice(k.compute_public_key().unwrap().as_ref())
    }

    fn dh(k: &Self::Key, pk: &Self::Pubkey) -> Result<Self::Output, Unspecified> {
        let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, pk);
        agreement::agree(k, &peer_public_key, Unspecified, |b| {
            Ok(Sensitive::from_slice(b))
        })
    }
}

const TAGLEN: usize = 16;

pub(crate) enum ChaCha20Poly1305 {}

impl Cipher for ChaCha20Poly1305 {
    fn name() -> &'static str {
        "ChaChaPoly"
    }

    type Key = LessSafeKey;

    fn key_len() -> usize {
        aead::CHACHA20_POLY1305.key_len()
    }

    fn key_from_slice(b: &[u8]) -> Self::Key {
        LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, b).unwrap())
    }

    fn encrypt(key: &Self::Key, nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut [u8]) {
        assert!(plaintext.len().checked_add(TAGLEN) == Some(out.len()));

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);


        let (in_out, tag_out) = out.split_at_mut(plaintext.len());
        in_out.copy_from_slice(plaintext);

        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(ad), in_out)
            .unwrap();
        tag_out.copy_from_slice(tag.as_ref());
    }

    fn encrypt_in_place(
        key: &Self::Key,
        nonce: u64,
        ad: &[u8],
        in_out: &mut [u8],
        plaintext_len: usize,
    ) -> usize {
        assert!(plaintext_len
            .checked_add(TAGLEN)
            .map_or(false, |l| l <= in_out.len()));

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);


        let (in_out, tag_out) = in_out[..plaintext_len + TAGLEN].split_at_mut(plaintext_len);
        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(ad), in_out)
            .unwrap();
        tag_out.copy_from_slice(tag.as_ref());

        plaintext_len + TAGLEN
    }

    fn decrypt(
        key: &Self::Key,
        nonce: u64,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<(), Unspecified> {
        assert!(ciphertext.len().checked_sub(TAGLEN) == Some(out.len()));

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = ciphertext.to_vec();

        let out0 = key
            .open_in_place(nonce, aead::Aad::from(ad), &mut in_out)
            .map_err(|_| Unspecified)?;

        out[..out0.len()].copy_from_slice(out0);
        Ok(())
    }

    fn decrypt_in_place(
        key: &Self::Key,
        nonce: u64,
        ad: &[u8],
        in_out: &mut [u8],
        ciphertext_len: usize,
    ) -> Result<usize, Unspecified> {
        assert!(ciphertext_len <= in_out.len());
        assert!(ciphertext_len >= TAGLEN);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        key.open_in_place(nonce, aead::Aad::from(ad), &mut in_out[..ciphertext_len])
            .map_err(|_| Unspecified)?;

        Ok(ciphertext_len - TAGLEN)
    }
}

pub(crate) struct Sensitive(Zeroizing<[u8; 32]>);

impl U8Array for Sensitive {
    fn new() -> Self {
        Sensitive(Zeroizing::new([0; 32]))
    }

    fn new_with(v: u8) -> Self {
        Sensitive(Zeroizing::new([v; 32]))
    }

    fn from_slice(s: &[u8]) -> Self {
        Sensitive(Zeroizing::new(s.try_into().unwrap()))
    }

    fn len() -> usize {
        32
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
