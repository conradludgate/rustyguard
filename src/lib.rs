use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::{borrow::Borrow, collections::HashMap, hash::BuildHasher};

use blake2::digest::consts::{U0, U12, U16, U32};
use blake2::digest::generic_array::GenericArray;
use bytemuck::{offset_of, Pod, Zeroable};
use chacha20poly1305::XNonce;
use ipnet::IpNet;
use rand::rngs::{OsRng, StdRng};
use rand::RngCore;
use utils::{hash, hkdf, mac, Bytes, Encrypted, HandshakeState, LEU32};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

mod utils;

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
    mac1_key: GenericArray<u8, U32>,
    mac2_key: GenericArray<u8, U32>,
    peers: HashMap<PublicKey, Peer2, SipHasher24>,
}

struct Peer2 {
    ips: Vec<IpNet>,
    preshared_key: GenericArray<u8, U32>,
}

pub struct Peer {
    key: PublicKey,
    allowed_source_ips: Vec<IpNet>,
    internet_endpoint: Option<SocketAddr>,
}

pub struct Sessions {
    config: Config,
    rng: StdRng,
    random_secret: GenericArray<u8, U32>,
    sessions: HashMap<PublicKeyWrapper, Session, SipHasher24>,
}

enum Session {
    Initiated(HandshakeState2),
    Completed(CipherState),
}

struct HandshakeState2 {
    sender: LEU32,
}

struct CipherState {}

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
const LABEL_MAC1: [u8; 8] = *b"mac1----";
const LABEL_COOKIE: [u8; 8] = *b"cookie--";

impl Sessions {
    fn overloaded(&self) -> bool {
        false
    }

    fn cookie(&self, socket: SocketAddr) -> GenericArray<u8, U16> {
        let ip_bytes = match socket.ip() {
            std::net::IpAddr::V4(ipv4) => &ipv4.octets()[..],
            std::net::IpAddr::V6(ipv6) => &ipv6.octets()[..],
        };
        mac(
            &self.random_secret,
            [ip_bytes, &socket.port().to_be_bytes()[..]],
        )
    }

    // TODO(conrad): enforce the msg is 4 byte aligned.
    pub fn recv_message<'m>(
        &mut self,
        socket: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<Message<'m>, Error> {
        if !msg.as_ptr().cast::<u32>().is_aligned() {
            return Err(Error::Unaligned);
        }

        let Some((msg_type, rest)) = msg.split_first_chunk_mut() else {
            return Err(Error::InvalidMessage);
        };
        let msg_type = u32::from_le_bytes(*msg_type);

        match msg_type {
            // First Message
            MSG_FIRST => match MacProtected::<FirstMessage>::verify(rest, self, socket)? {
                ControlFlow::Break(cookie) => {
                    let cookie_msg = &mut msg[..core::mem::size_of::<CookieMessage>()];
                    cookie_msg.copy_from_slice(bytemuck::bytes_of(&cookie));
                    return Ok(Message::Response(&*cookie_msg));
                }
                ControlFlow::Continue((sender, first)) => {
                    let (_hs, response) = first.process(sender, &self.config)?;
                    let sender_static_key = first.static_key.assumed_decrypted();
                    let sender_static_key = PublicKey::from(<[u8; 32]>::from(*sender_static_key));

                    // TODO: derive cipher keys from hs
                    self.sessions.insert(
                        PublicKeyWrapper(sender_static_key),
                        Session::Completed(CipherState {}),
                    );

                    let resp = MacProtected::new(LEU32::new(0), response, None, &self.config);

                    let resp_msg = &mut msg[..core::mem::size_of::<MacProtected<SecondMessage>>()];
                    resp_msg.copy_from_slice(bytemuck::bytes_of(&resp));
                    return Ok(Message::Response(&*resp_msg));
                }
            },
            // Second Message
            MSG_SECOND => match MacProtected::<SecondMessage>::verify(rest, self, socket)? {
                ControlFlow::Break(cookie) => {
                    let cookie_msg = &mut msg[..core::mem::size_of::<CookieMessage>()];
                    cookie_msg.copy_from_slice(bytemuck::bytes_of(&cookie));
                    return Ok(Message::Response(&*cookie_msg));
                }
                ControlFlow::Continue((sender, second)) => {}
            },
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

#[derive(Pod, Zeroable, Clone, Copy)]
#[repr(C)]
struct FirstMessage {
    ephemeral_key: [u8; 32],
    static_key: Encrypted<U32>,
    timestamp: Encrypted<U12>,
}

#[derive(Pod, Zeroable, Clone, Copy)]
#[repr(C)]
struct CookieMessage {
    receiver: LEU32,
    nonce: Bytes<chacha20poly1305::consts::U24>,
    cookie: Encrypted<U16>,
}

impl CookieMessage {
    fn new(
        receiver: LEU32,
        state: &mut Sessions,
        socket: SocketAddr,
        mac1: &GenericArray<u8, U16>,
    ) -> Self {
        let t = state.cookie(socket);
        let mut nonce = XNonce::default();
        state.rng.fill_bytes(&mut nonce);
        let cookie = Encrypted::encrypt_cookie(t, &state.config.mac2_key, &nonce, mac1);

        Self {
            receiver,
            nonce: Bytes(nonce),
            cookie,
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct MacProtected<T> {
    sender: LEU32,
    inner: T,
    mac1: Bytes<U16>,
    mac2: Bytes<U16>,
}

unsafe impl Pod for MacProtected<FirstMessage> {}
unsafe impl Zeroable for MacProtected<FirstMessage> {}
unsafe impl Pod for MacProtected<SecondMessage> {}
unsafe impl Zeroable for MacProtected<SecondMessage> {}

impl<T> MacProtected<T>
where
    Self: Pod,
{
    pub fn new(
        sender: LEU32,
        msg: T,
        cookie: Option<&GenericArray<u8, U16>>,
        config: &Config,
    ) -> Self {
        let mut mac = Self {
            sender,
            inner: msg,
            mac1: Bytes(GenericArray::default()),
            mac2: Bytes(GenericArray::default()),
        };
        mac.mac1.0 = mac.mac1(&config.mac1_key);
        if let Some(cookie) = cookie {
            mac.mac2.0 = mac.mac2(cookie);
        }
        mac
    }

    pub fn verify<'m>(
        msg: &'m mut [u8],
        state: &mut Sessions,
        socket: SocketAddr,
    ) -> Result<ControlFlow<CookieMessage, (LEU32, &'m mut T)>, Error> {
        let mac: &'m mut MacProtected<T> =
            bytemuck::try_from_bytes_mut(msg).map_err(|_| Error::InvalidMessage)?;

        mac.verify_mac1(&state.config)?;
        if state.overloaded() && mac.verify_mac2(state, socket).is_err() {
            let cookie = CookieMessage::new(mac.sender, state, socket, &mac.mac1.0);
            Ok(ControlFlow::Break(cookie))
        } else {
            Ok(ControlFlow::Continue((mac.sender, &mut mac.inner)))
        }
    }

    fn verify_mac1(&self, config: &Config) -> Result<(), Error> {
        use subtle::ConstantTimeEq;
        let actual_mac1 = self.mac1(&config.mac1_key);
        if actual_mac1.ct_ne(&self.mac1.0).into() {
            Err(Error::Rejected)
        } else {
            Ok(())
        }
    }

    fn verify_mac2(&self, state: &Sessions, socket: SocketAddr) -> Result<(), Error> {
        use subtle::ConstantTimeEq;
        let cookie = state.cookie(socket);
        let actual_mac2 = self.mac2(&cookie);
        if actual_mac2.ct_ne(&self.mac2.0).into() {
            Err(Error::Rejected)
        } else {
            Ok(())
        }
    }

    fn mac1(&self, mac1_key: &GenericArray<u8, U32>) -> GenericArray<u8, U16> {
        let offset = offset_of!(self, MacProtected<T>, mac1);
        let bytes = bytemuck::bytes_of(self);
        mac(mac1_key, [&bytes[..offset]])
    }

    fn mac2(&self, cookie: &GenericArray<u8, U16>) -> GenericArray<u8, U16> {
        let offset = offset_of!(self, MacProtected<T>, mac2);
        let bytes = bytemuck::bytes_of(self);
        mac(cookie, [&bytes[..offset]])
    }
}

fn mac1_key(spk: &PublicKey) -> GenericArray<u8, U32> {
    hash([&LABEL_MAC1, spk.as_bytes()])
}
fn mac2_key(spk: &PublicKey) -> GenericArray<u8, U32> {
    hash([&LABEL_COOKIE, spk.as_bytes()])
}

impl FirstMessage {
    fn process(
        &mut self,
        sender: LEU32,
        config: &Config,
    ) -> Result<(HandshakeState, SecondMessage), Error> {
        let mut hs = HandshakeState::default();
        hs.mix_hash(config.public_key.as_bytes());
        hs.mix_chain(&self.ephemeral_key);
        hs.mix_hash(&self.ephemeral_key);

        let epk_i = PublicKey::from(self.ephemeral_key);
        let k = hs.mix_key_dh(&config.private_key, &epk_i);

        let spk_i = self.static_key.decrypt_and_hash(&mut hs, &k)?;
        let spk_i = PublicKey::from(<[u8; 32]>::from(*spk_i));

        let k = hs.mix_key_dh(&config.private_key, &spk_i);
        let timestamp = self.static_key.decrypt_and_hash(&mut hs, &k)?;

        let Some(peer) = config.peers.get(&spk_i) else {
            return Err(Error::Rejected);
        };

        let esk_r = StaticSecret::random_from_rng(OsRng);
        let epk_r = PublicKey::from(&esk_r);
        hs.mix_chain(epk_r.as_bytes());
        hs.mix_hash(epk_r.as_bytes());
        hs.mix_dh(&esk_r, &epk_i);
        hs.mix_dh(&esk_r, &epk_i);
        let q = peer.preshared_key;
        let k = hs.mix_key2(&q);
        let empty = Encrypted::encrypt_and_hash(GenericArray::<u8, U0>::default(), &mut hs, &k);

        let second = SecondMessage {
            receiver: sender,
            ephemeral_key: epk_r.to_bytes(),
            empty,
        };

        Ok((hs, second))
    }
}

#[derive(Pod, Zeroable, Clone, Copy)]
#[repr(C)]
struct SecondMessage {
    receiver: LEU32,
    ephemeral_key: [u8; 32],
    empty: Encrypted<U0>,
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

#[cfg(test)]
mod tests {
    use blake2::Digest;

    use crate::{CookieMessage, FirstMessage, MacProtected, SecondMessage};

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
    fn test_size_align() {
        assert_eq!(core::mem::size_of::<MacProtected<FirstMessage>>(), 144);
        assert_eq!(core::mem::align_of::<MacProtected<FirstMessage>>(), 4);

        assert_eq!(core::mem::size_of::<MacProtected<SecondMessage>>(), 88);
        assert_eq!(core::mem::align_of::<MacProtected<SecondMessage>>(), 4);

        assert_eq!(core::mem::size_of::<CookieMessage>(), 60);
        assert_eq!(core::mem::align_of::<CookieMessage>(), 4);
    }
}
