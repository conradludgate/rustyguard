use std::{borrow::Borrow, collections::HashMap, hash::BuildHasher};

// use aws_lc_rs::{
//     aead::{
//         self,
//         nonce_sequence::{Counter64, Counter64Builder},
//         Aad, BoundKey, OpeningKey, UnboundKey,
//     },
//     agreement::{self, PrivateKey, PublicKey},
// };
use blake2::digest::consts::{U12, U28, U32, U48};
use blake2::digest::generic_array::ArrayLength;
use blake2::digest::generic_array::{sequence::Split, GenericArray};
use blake2::digest::{core_api::Block, Digest, Output};
use blake2::Blake2s256;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce, Tag};
use ipnet::IpNet;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zerocopy::{little_endian, FromBytes};
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};

// mod noise_lc;

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
pub struct PublicKeyWrapper(PublicKey);

impl Borrow<[u8]> for PublicKeyWrapper {
    fn borrow(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

struct SipHasher24(u64, u64);

impl BuildHasher for SipHasher24 {
    type Hasher = siphasher::sip::SipHasher24;

    fn build_hasher(&self) -> Self::Hasher {
        siphasher::sip::SipHasher24::new_with_keys(self.0, self.1)
    }
}

pub struct Config {
    private_key: StaticSecret,
    public_key: PublicKey,
    peers: HashMap<PublicKeyWrapper, Vec<IpNet>, SipHasher24>,
}

pub struct Sessions {
    config: Config,
    sessions: HashMap<PublicKeyWrapper, (), SipHasher24>,
}

enum Session {
    Initiated(HandshakeState),
    Completed(CipherState),
}

struct HandshakeState;
struct CipherState;

pub enum Error {
    InvalidMessage,
    Unspecified,
    Unaligned,
    Rejected,
}

pub enum Message<'a> {
    Response(&'a [u8]),
    Process(&'a [u8]),
}

const MSG_FIRST: u32 = 1;
const MSG_SECOND: u32 = 2;
const MSG_DATA: u32 = 3;
const MSG_COOKIE: u32 = 4;

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

impl Sessions {
    // TODO(conrad): enforce the msg is 4 byte aligned.
    pub fn recv_message(&mut self, msg: &mut [u8]) -> Result<Message, Error> {
        if !msg.as_ptr().cast::<u32>().is_aligned() {
            return Err(Error::Unaligned);
        }

        let Some((msg_type, rest)) = msg.split_first_chunk_mut() else {
            return Err(Error::InvalidMessage);
        };
        let msg_type = u32::from_le_bytes(*msg_type);

        match msg_type {
            // First Message
            MSG_FIRST => {
                let Some(first_message) = FirstMessage::mut_from(rest) else {
                    return Err(Error::InvalidMessage);
                };
                let (c, h) = first_message.process(&self.config)?;

                if !self
                    .config
                    .peers
                    .contains_key(&first_message.static_key[..32])
                {
                    return Err(Error::Rejected);
                }
            }
            // Second Message
            MSG_SECOND => {}
            // Data Message
            MSG_DATA => {}
            // Cookie
            MSG_COOKIE => {}
            // Unknown
            _ => return Err(Error::InvalidMessage),
        }

        todo!()
    }
}

#[derive(FromBytes, FromZeroes, AsBytes)]
#[repr(C)]
struct FirstMessage {
    sender: little_endian::U32,
    ephemeral_key: [u8; 32],
    static_key: [u8; 32 + 16],
    timestamp: [u8; 12 + 16],
    mac1: [u8; 16],
    mac2: [u8; 16],
}

impl FirstMessage {
    fn process(
        &mut self,
        config: &Config,
    ) -> Result<(GenericArray<u8, U32>, GenericArray<u8, U32>), Error> {
        let c = GenericArray::from(CONSTRUCTION_HASH);
        let h = GenericArray::<u8, U32>::from(IDENTIFIER_HASH);
        let h = hash([&*h, config.public_key.as_ref()]);
        let [c] = hkdf(&c, [&self.ephemeral_key]);
        let h = hash([&h, &self.ephemeral_key]);

        let epk_i = PublicKey::from(self.ephemeral_key);
        let prk = config.private_key.diffie_hellman(&epk_i);
        let [c, k] = hkdf(&c, [prk.as_bytes()]);

        let aad = h;
        let h = hash([&h, &self.static_key]);

        let static_key = GenericArray::<u8, U48>::from(self.static_key);
        let (mut spk_i, tag) = static_key.split();
        ChaCha20Poly1305::new(&k).decrypt_in_place_detached(&nonce(0), &aad, &mut spk_i, &tag);

        let spk_i = PublicKey::from(<[u8; 32]>::from(spk_i));
        let prk = config.private_key.diffie_hellman(&spk_i);
        let [c, k] = hkdf(&c, [prk.as_bytes()]);

        let aad = h;
        let h = hash([&h, &self.timestamp]);

        let timestamp = GenericArray::<u8, U28>::from(self.timestamp);
        let (mut timestamp, tag): (GenericArray<u8, U12>, Tag) = timestamp.split();
        ChaCha20Poly1305::new(&k).decrypt_in_place_detached(&nonce(0), &aad, &mut timestamp, &tag);

        Ok((c, h))
    }
}

#[derive(FromBytes, FromZeroes, AsBytes)]
#[repr(C)]
struct SecondMessage {
    sender: little_endian::U32,
    receiver: little_endian::U32,
    ephemeral_key: [u8; 32],
    empty: [u8; 16],
    mac1: [u8; 16],
    mac2: [u8; 16],
}

impl SecondMessage {
    fn construct(
        config: &Config,
        first_message: &FirstMessage,
        c: GenericArray<u8, U32>,
        h: GenericArray<u8, U32>,
    ) -> Result<(GenericArray<u8, U32>, GenericArray<u8, U32>), Error> {
        let esk = EphemeralSecret::random();
        let epk = PublicKey::from(&esk);

        let [c] = hkdf(&c, [epk.as_bytes()]);

        // let c = GenericArray::from(CONSTRUCTION_HASH);
        // let h = GenericArray::from(IDENTIFIER_HASH);
        // let h = hash([&h, config.public_key.as_ref()]);
        // let [c] = hkdf(&c, [&self.ephemeral_key]);
        // let h = hash([&h, &self.ephemeral_key]);

        // let [c, k] = kdf_dh(&config.private_key, self.ephemeral_key, &c)?;

        // let aad = Aad::from(h);
        // let h = hash([&h, &self.static_key]);

        // let peer_static_key = opening_key(k, 0)?
        //     .open_in_place(aad, &mut self.static_key)
        //     .map_err(|_: aws_lc_rs::error::Unspecified| Error::Unspecified)?;
        // let [c, k] = kdf_dh(&config.private_key, peer_static_key, &c)?;

        // let aad = Aad::from(h);
        // let h = hash([&h, &self.timestamp]);

        // opening_key(k, 0)?
        //     .open_in_place(aad, &mut self.timestamp)
        //     .map_err(|_: aws_lc_rs::error::Unspecified| Error::Unspecified)?;

        Ok((c, h))
    }
}

fn nonce(counter: u64) -> Nonce {
    let mut n = Nonce::default();
    n[4..].copy_from_slice(&u64::to_le_bytes(counter));
    n
}

fn hash<const M: usize>(msg: [&[u8]; M]) -> Output<Blake2s256> {
    let mut digest = Blake2s256::default();
    for msg in msg {
        digest.update(msg);
    }
    digest.finalize()
}

fn hmac<const M: usize>(key: &GenericArray<u8, U32>, msg: [&[u8]; M]) -> Output<Blake2s256> {
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5C;

    let mut buf = Block::<Blake2s256>::default();
    buf[..32].copy_from_slice(key);
    for b in buf.iter_mut() {
        *b ^= IPAD;
    }
    let mut digest = Blake2s256::default();
    digest.update(&buf);

    for b in buf.iter_mut() {
        *b ^= IPAD ^ OPAD;
    }

    let mut opad_digest = Blake2s256::default();
    opad_digest.update(&buf);

    for msg in msg {
        digest.update(msg);
    }

    opad_digest.chain_update(digest.finalize()).finalize()
}

fn hkdf<const N: usize, const M: usize>(
    key: &GenericArray<u8, U32>,
    msg: [&[u8]; M],
) -> [Output<Blake2s256>; N] {
    assert!(N <= 255);
    assert!(N >= 1);

    let mut output = [Output::<Blake2s256>::default(); N];

    let t0 = hmac(key, msg);
    let mut ti = hmac(&t0, [&[1]]);
    output[0] = ti;
    for i in 1..N as u8 {
        ti = hmac(&t0, [&ti, &[i + 1]]);
        output[i as usize] = ti;
    }

    output
}

#[repr(C)]
struct ZeroCopyBytes<U: ArrayLength<u8>>(GenericArray<u8, U>);

unsafe impl<U: ArrayLength<u8>> zerocopy::FromBytes for ZeroCopyBytes<U> {
    fn only_derive_is_allowed_to_implement_this_trait()
    where
        Self: Sized,
    {
    }
}

unsafe impl<U: ArrayLength<u8>> zerocopy::FromZeroes for ZeroCopyBytes<U> {
    fn only_derive_is_allowed_to_implement_this_trait()
    where
        Self: Sized,
    {
    }
}

unsafe impl<U: ArrayLength<u8>> zerocopy::AsBytes for ZeroCopyBytes<U> {
    fn only_derive_is_allowed_to_implement_this_trait()
    where
        Self: Sized,
    {
    }
}

#[cfg(test)]
mod tests {
    use blake2::Digest;

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
}
