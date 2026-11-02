#![no_std]

use core::{marker::PhantomData, net::SocketAddr, ops::ControlFlow};

pub use prim::{DecryptionKey, EncryptionKey, HandshakeState, Key, Mac};
use prim::{Encrypted, LABEL_COOKIE, LABEL_MAC1};

/// Transport packets at or above this counter must be rejected and keys renewed.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

use rand_core::CryptoRng;
use rustyguard_types::{
    Cookie, EncryptedCookie, EncryptedEmpty, EncryptedPublicKey, EncryptedTimestamp, HandshakeInit,
    HandshakeResp, Tag, MSG_FIRST, MSG_SECOND,
};

use tai64::Tai64N;
use zerocopy::{little_endian, FromBytes, IntoBytes};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(any(test, rustyguard_unsafe_logging))]
extern crate std;

/// Internal debug-trace macro. The output is "unsafe" because it can leak
/// keying material, peer identifiers, and other secrets — never enable it
/// in production.
///
/// It is a no-op unless one of the following is true:
/// * the crate is built under `cfg(test)`, or
/// * the consumer sets `--cfg rustyguard_unsafe_logging`.
macro_rules! unsafe_log {
    ($($t:tt)*) => {
        match core::format_args!($($t)*) {
            #[cfg(any(test, rustyguard_unsafe_logging))]
            args => std::eprintln!("{args}"),
            #[cfg(not(any(test, rustyguard_unsafe_logging)))]
            _ => {}
        };
    }
}

mod prim;
pub use prim::{CryptoPrimatives, PublicKey, StaticPrivateKey};
pub mod providers;
/// An X25519 agreement result, rejected if all zero and erased on drop.
///
/// Construct this from the device's 32-byte output. This does not verify that
/// the device performed the requested agreement or erase copies kept by it.
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret(Key);

impl SharedSecret {
    pub fn new(mut bytes: Key) -> Result<Self, CryptoError> {
        if constant_time_eq::constant_time_eq_32(&bytes, &[0; 32]) {
            bytes.zeroize();
            return Err(CryptoError::KeyExchangeError);
        }
        Ok(Self(bytes))
    }

    fn as_bytes(&self) -> &Key {
        &self.0
    }
}

#[cfg(test)]
mod shared_secret_tests {
    use super::*;

    #[test]
    fn shared_secret_rejects_all_zero_output() {
        assert!(matches!(
            SharedSecret::new([0; 32]),
            Err(CryptoError::KeyExchangeError)
        ));
        for index in 0..32 {
            let mut bytes = [0; 32];
            bytes[index] = 1;
            assert_eq!(SharedSecret::new(bytes).unwrap().as_bytes(), &bytes);
        }
    }
}

/// Default provider: Graviola when enabled, otherwise RustCrypto.
#[cfg(feature = "graviola")]
pub use providers::Graviola as CryptoCore;
/// Default provider when only the portable backend is enabled.
#[cfg(all(not(feature = "graviola"), feature = "rustcrypto"))]
pub use providers::RustCrypto as CryptoCore;
/// No built-in provider is selected. Supply your provider type explicitly.
#[cfg(not(any(feature = "graviola", feature = "rustcrypto")))]
pub struct CryptoCore;
pub struct EphemeralPrivateKey(StaticPrivateKey);

#[derive(Debug)]
pub enum CryptoError {
    KeyExchangeError,
    DecryptionError,
    Rejected,
}

/// Decrypt a cookie using the default crypto provider.
#[cfg(any(feature = "graviola", feature = "rustcrypto"))]
pub fn decrypt_cookie<'c>(
    cookie: &'c mut EncryptedCookie,
    key: &Key,
    nonce: &[u8; 24],
    aad: &[u8],
) -> Result<&'c mut Cookie, CryptoError> {
    decrypt_cookie_with::<CryptoCore>(cookie, key, nonce, aad)
}

/// Encrypt a cookie using the default crypto provider.
#[cfg(any(feature = "graviola", feature = "rustcrypto"))]
pub fn encrypt_cookie(cookie: Cookie, key: &Key, nonce: &[u8; 24], aad: &[u8]) -> EncryptedCookie {
    encrypt_cookie_with::<CryptoCore>(cookie, key, nonce, aad)
}

/// Derive a peer's MAC1 key using the default crypto provider.
#[cfg(any(feature = "graviola", feature = "rustcrypto"))]
pub fn mac1_key(spk: &[u8]) -> Key {
    mac1_key_with::<CryptoCore>(spk)
}

/// Derive a peer's cookie key using the default crypto provider.
#[cfg(any(feature = "graviola", feature = "rustcrypto"))]
pub fn cookie_key(spk: &[u8]) -> Key {
    cookie_key_with::<CryptoCore>(spk)
}

pub fn decrypt_cookie_with<'c, C: CryptoPrimatives>(
    cookie: &'c mut EncryptedCookie,
    key: &Key,
    nonce: &[u8; 24],
    aad: &[u8],
) -> Result<&'c mut Cookie, CryptoError> {
    C::xchacha20poly1305_dec(key, nonce, aad, &mut cookie.msg.0, &cookie.tag.0)?;

    Ok(&mut cookie.msg)
}

pub fn encrypt_cookie_with<C: CryptoPrimatives>(
    cookie: Cookie,
    key: &Key,
    nonce: &[u8; 24],
    aad: &[u8],
) -> EncryptedCookie {
    let mut out = EncryptedCookie {
        msg: cookie,
        tag: Tag([0; 16]),
    };

    C::xchacha20poly1305_enc(key, nonce, aad, &mut out.msg.0, &mut out.tag.0);

    out
}

pub fn mac1_key_with<C: CryptoPrimatives>(spk: &[u8]) -> Key {
    C::blake2s_hash(&LABEL_MAC1, spk)
}
pub fn cookie_key_with<C: CryptoPrimatives>(spk: &[u8]) -> Key {
    C::blake2s_hash(&LABEL_COOKIE, spk)
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CookieState {
    key: Key,
}

impl CookieState {
    pub fn new(rng: &mut impl CryptoRng) -> Self {
        let mut key = Key::default();
        rng.fill_bytes(&mut key);
        Self { key }
    }

    pub fn generate(&mut self, rng: &mut impl CryptoRng) {
        rng.fill_bytes(&mut self.key);
    }

    /// Create an address-bound cookie using the default provider.
    #[cfg(any(feature = "graviola", feature = "rustcrypto"))]
    pub fn new_cookie(&self, addr: SocketAddr) -> Cookie {
        self.new_cookie_with::<CryptoCore>(addr)
    }

    /// Create an address-bound cookie using a selected provider.
    pub fn new_cookie_with<C: CryptoPrimatives>(&self, addr: SocketAddr) -> Cookie {
        // there's no specified encoding here - it just needs to contain the IP address and port :shrug:
        let mut a = [0; 18];
        match addr.ip() {
            core::net::IpAddr::V4(ipv4) => a[..4].copy_from_slice(&ipv4.octets()[..]),
            core::net::IpAddr::V6(ipv6) => a[..16].copy_from_slice(&ipv6.octets()[..]),
        }
        a[16..].copy_from_slice(&addr.port().to_le_bytes()[..]);
        Cookie(C::blake2s_mac(&self.key, &a))
    }
}

/// Both handshake messages are protected via MACs which can quickly be used
/// to rule out invalid messages.
///
/// The first MAC verifies that the message is even valid - to not waste time.
/// The second MAC is only checked if the server is overloaded. If the server is
/// overloaded and second MAC is invalid, a CookieReply is sent to the client,
/// which contains an encrypted key that can be used to re-sign the handshake later.
pub trait HasMac: FromBytes + IntoBytes + Sized {
    fn verify<'m, C: CryptoPrimatives>(
        &'m mut self,
        config: &StaticInitiatorConfig<C>,
        overload: bool,
        cookie: &CookieState,
        addr: SocketAddr,
    ) -> Result<ControlFlow<Cookie, &'m mut Self>, CryptoError> {
        self.verify_with::<C>(&config.mac1_key, overload, cookie, addr)
    }

    /// Verify admission using a cached local MAC1 key, without any private key.
    /// Derive it once with [`mac1_key_with`] from the local public key.
    fn verify_with<'m, C: CryptoPrimatives>(
        &'m mut self,
        mac1_key: &Key,
        overload: bool,
        cookie: &CookieState,
        addr: SocketAddr,
    ) -> Result<ControlFlow<Cookie, &'m mut Self>, CryptoError> {
        // verify the mac1. this should be very fast.
        // takes 450ns on my M2 Max.
        // Thus, can handle ~2 million handshakes per second.
        // This is currently single threaded.
        // TODO(conrad): need to make the rejection multi-threaded.
        self.verify_mac1::<C>(mac1_key)?;

        if overload {
            // Will be roughly twice as slow as verify_mac1. 750ns on my M2 Max.
            // If the server is overloaded, this is good for rejecting DDoS attacks
            // as it requires a round trip from the sender.
            let cookie = cookie.new_cookie_with::<C>(addr);
            if self.verify_mac2::<C>(&cookie).is_err() {
                return Ok(ControlFlow::Break(cookie));
            }
        }

        Ok(ControlFlow::Continue(self))
    }

    fn verify_mac1<C: CryptoPrimatives>(&self, mac1_key: &Key) -> Result<(), CryptoError> {
        let actual_mac1 = self.compute_mac1::<C>(mac1_key);
        if &actual_mac1 != self.get_mac1() {
            unsafe_log!("invalid mac1");
            Err(CryptoError::Rejected)
        } else {
            unsafe_log!("valid mac1");
            Ok(())
        }
    }

    fn verify_mac2<C: CryptoPrimatives>(&self, cookie: &Cookie) -> Result<(), CryptoError> {
        let actual_mac2 = self.compute_mac2::<C>(cookie);
        if &actual_mac2 != self.get_mac2() {
            unsafe_log!("invalid mac2");
            Err(CryptoError::Rejected)
        } else {
            unsafe_log!("valid mac2");
            Ok(())
        }
    }

    fn compute_mac1<C: CryptoPrimatives>(&self, mac1_key: &Key) -> Mac;
    fn compute_mac2<C: CryptoPrimatives>(&self, cookie: &Cookie) -> Mac;
    fn get_mac1(&self) -> &Mac;
    fn get_mac2(&self) -> &Mac;
}

macro_rules! mac_protected {
    ($i:ident, $t:ident) => {
        // The wire format pins mac1 and mac2 as the two trailing 16-byte
        // fields of every handshake message. compute_mac1/compute_mac2 sign
        // everything *up to* their respective offset, so a future layout
        // change that reordered or repadded these fields would silently
        // produce wrong macs and break interop. Catch that at compile time.
        const _: () =
            assert!(core::mem::offset_of!($i, mac1) + 16 == core::mem::offset_of!($i, mac2));
        const _: () = assert!(core::mem::offset_of!($i, mac2) + 16 == core::mem::size_of::<$i>());

        impl HasMac for $i {
            fn compute_mac1<C: CryptoPrimatives>(&self, mac1_key: &crate::Key) -> Mac {
                let offset = core::mem::offset_of!($i, mac1);
                let bytes = self.as_bytes();
                C::blake2s_mac(mac1_key, &bytes[..offset])
            }

            fn compute_mac2<C: CryptoPrimatives>(&self, cookie: &Cookie) -> Mac {
                let offset = core::mem::offset_of!($i, mac2);
                let bytes = self.as_bytes();
                C::blake2s_mac(&cookie.0, &bytes[..offset])
            }

            fn get_mac1(&self) -> &Mac {
                &self.mac1
            }

            fn get_mac2(&self) -> &Mac {
                &self.mac2
            }
        }
    };
}

mac_protected!(HandshakeInit, MSG_FIRST);
mac_protected!(HandshakeResp, MSG_SECOND);

// ---- Noise IKpsk2 ---- //
// Wireguard makes use of the Noise IKpsk2 handshake.
// Read the noise specification: https://noiseprotocol.org/noise.html
//
// The IKpsk2 pattern is as follows:
// <- s
// -> e, es, s, ss
// <- e, ee, se, psk
//
// The initiator is expected to know the responder's static public key prior to the handshake.
// The initiator sends an ephemeral public key and their encrypted static public key.
// The responder sends an ephemeral public key.

pub struct StaticPeerConfig {
    /// Peer's public key.
    pub key: PublicKey,
    /// Peer's preshared key.
    pub preshared_key: Key,
    /// Cached mac1_key: calculated using `mac1_key(&self.key)`
    pub mac1_key: Key,
    /// Cached cookie_key: calculated using `cookie_key(&self.key)`
    pub cookie_key: Key,
    /// Default internet endpoint
    pub endpoint: Option<SocketAddr>,
}

pub struct StaticInitiatorConfig<C = CryptoCore> {
    _crypto: PhantomData<fn() -> C>,
    /// Our private key.
    pub private_key: StaticPrivateKey,
    /// Cached public key, derived from the above private key.
    pub public_key: PublicKey,
    /// Cached mac1_key: calculated using `mac1_key(&self.public_key)`
    pub mac1_key: Key,
    /// Cached cookie_key: calculated using `cookie_key(&self.public_key)`
    pub cookie_key: Key,
}

impl StaticPeerConfig {
    #[cfg(any(feature = "graviola", feature = "rustcrypto"))]
    pub fn new(key: PublicKey, preshared_key: Option<Key>, endpoint: Option<SocketAddr>) -> Self {
        Self::with_crypto::<CryptoCore>(key, preshared_key, endpoint)
    }

    /// Construct peer key caches using the selected crypto provider.
    pub fn with_crypto<C: CryptoPrimatives>(
        key: PublicKey,
        preshared_key: Option<Key>,
        endpoint: Option<SocketAddr>,
    ) -> Self {
        Self {
            mac1_key: mac1_key_with::<C>(&key.0),
            cookie_key: cookie_key_with::<C>(&key.0),
            key,
            preshared_key: preshared_key.unwrap_or_default(),
            endpoint,
        }
    }
}

#[cfg(any(feature = "graviola", feature = "rustcrypto"))]
impl StaticInitiatorConfig {
    pub fn new(key: StaticPrivateKey) -> Self {
        Self::with_crypto(key)
    }
}

impl<C: CryptoPrimatives> StaticInitiatorConfig<C> {
    /// Construct the local identity using this configuration's crypto provider.
    pub fn with_crypto(key: StaticPrivateKey) -> Self {
        let public_key = C::x25519_pubkey(&key);
        Self {
            mac1_key: mac1_key_with::<C>(&public_key.0),
            cookie_key: cookie_key_with::<C>(&public_key.0),
            public_key,
            private_key: key,
            _crypto: PhantomData,
        }
    }
}

/// An outgoing initiation waiting for static/static DH with [`Self::peer_key`].
/// The caller keeps its private key and initiating ephemeral key. Consume this
/// state with [`Self::complete`], or drop it to abandon the handshake.
#[must_use]
pub struct EncryptHandshakeInit<C> {
    state: HandshakeState,
    message: HandshakeInit,
    peer: PublicKey,
    mac1_key: Key,
    cookie: Option<Cookie>,
    _crypto: PhantomData<fn() -> C>,
}

impl<C: CryptoPrimatives> EncryptHandshakeInit<C> {
    pub fn new(
        mut state: HandshakeState,
        public_key: &PublicKey,
        peer: &StaticPeerConfig,
        esk_i: &EphemeralPrivateKey,
        now: Tai64N,
        sender: u32,
        cookie: Option<&Cookie>,
    ) -> Result<Self, CryptoError> {
        let hs = &mut state;

        // <- s; -> e, es, s. Only the following ss token uses the local static key.
        let epk_i = C::x25519_pubkey(&esk_i.0);
        hs.mix_hash::<C>(&peer.key.0);
        hs.mix_hash::<C>(&epk_i.0);
        hs.mix_chain::<C>(&epk_i.0);
        let k = Zeroizing::new(hs.mix_key_edh::<C>(esk_i, &peer.key)?);
        let static_key = EncryptedPublicKey::encrypt_and_hash::<C>(public_key.0, hs, &k);

        let message = HandshakeInit {
            _type: little_endian::U32::new(MSG_FIRST),
            sender: little_endian::U32::new(sender),
            ephemeral_key: epk_i.0,
            static_key,
            // Encrypt this after the ss agreement completes.
            timestamp: EncryptedTimestamp {
                msg: now.to_bytes(),
                tag: rustyguard_types::Tag([0; 16]),
            },
            mac1: [0; 16],
            mac2: [0; 16],
        };
        Ok(Self {
            state,
            message,
            peer: PublicKey(peer.key.0),
            mac1_key: peer.mac1_key,
            cookie: cookie.copied(),
            _crypto: PhantomData,
        })
    }

    pub fn peer_key(&self) -> PublicKey {
        PublicKey(self.peer.0)
    }

    /// Complete with DH using the local static key matching the public key
    /// supplied at construction. Keep the returned transcript for the response.
    pub fn complete(mut self, secret: SharedSecret) -> (HandshakeInit, HandshakeState) {
        let k = Zeroizing::new(self.state.mix_key::<C>(secret.as_bytes()));
        self.message.timestamp = EncryptedTimestamp::encrypt_and_hash::<C>(
            self.message.timestamp.msg,
            &mut self.state,
            &k,
        );
        self.message.mac1 = self.message.compute_mac1::<C>(&self.mac1_key);
        if let Some(cookie) = self.cookie.as_ref() {
            self.message.mac2 = self.message.compute_mac2::<C>(cookie);
        }
        (self.message, self.state)
    }
}

/// A received initiation waiting for static/ephemeral DH.
/// Perform MAC/cookie/rate admission first. Completion decrypts only a claimed
/// identity, which is not yet an authenticated peer.
#[must_use]
pub struct DecryptHandshakeInit<C> {
    state: HandshakeState,
    message: HandshakeInit,
    _crypto: PhantomData<fn() -> C>,
}
impl<C: CryptoPrimatives> DecryptHandshakeInit<C> {
    pub fn new(message: HandshakeInit, mut state: HandshakeState, public_key: &PublicKey) -> Self {
        state.mix_hash::<C>(&public_key.0);
        state.mix_hash::<C>(&message.ephemeral_key);
        state.mix_chain::<C>(&message.ephemeral_key);
        Self {
            state,
            message,
            _crypto: PhantomData,
        }
    }
    pub fn peer_key(&self) -> PublicKey {
        PublicKey(self.message.ephemeral_key)
    }
    pub fn complete(
        mut self,
        secret: SharedSecret,
    ) -> Result<DecryptHandshakeTimestamp<C>, CryptoError> {
        let k = Zeroizing::new(self.state.mix_key::<C>(secret.as_bytes()));
        self.message
            .static_key
            .decrypt_and_hash::<C>(&mut self.state, &k)?;
        Ok(DecryptHandshakeTimestamp {
            state: self.state,
            message: self.message,
            _crypto: PhantomData,
        })
    }
}

/// An initiation waiting for static/static DH to authenticate its timestamp.
/// Only the preceding state's completion constructs this stage. Use the same
/// local static key; [`Self::peer_key`] is still only a claimed identity.
#[must_use]
pub struct DecryptHandshakeTimestamp<C> {
    state: HandshakeState,
    message: HandshakeInit,
    _crypto: PhantomData<fn() -> C>,
}
impl<C: CryptoPrimatives> DecryptHandshakeTimestamp<C> {
    pub fn peer_key(&self) -> PublicKey {
        PublicKey(self.message.static_key.msg)
    }
    pub fn complete(
        mut self,
        secret: SharedSecret,
    ) -> Result<DecryptedHandshakeInit<C>, CryptoError> {
        let k = Zeroizing::new(self.state.mix_key::<C>(secret.as_bytes()));
        self.message
            .timestamp
            .decrypt_and_hash::<C>(&mut self.state, &k)?;
        Ok(DecryptedHandshakeInit {
            state: self.state,
            message: self.message,
            _crypto: PhantomData,
        })
    }
}

/// An authenticated initiation and its owned transcript, ready to respond.
/// Check the known peer, timestamp ordering and job liveness before responding.
#[must_use]
pub struct DecryptedHandshakeInit<C> {
    state: HandshakeState,
    message: HandshakeInit,
    _crypto: PhantomData<fn() -> C>,
}
impl<C: CryptoPrimatives> DecryptedHandshakeInit<C> {
    pub fn static_key(&self) -> PublicKey {
        PublicKey(self.message.static_key.msg)
    }
    pub fn timestamp(&self) -> &[u8; 12] {
        &self.message.timestamp.msg
    }

    /// Consume the authenticated initiation to produce a response and completed
    /// transcript. These DH operations use the responding ephemeral private key.
    pub fn respond(
        mut self,
        esk_r: &EphemeralPrivateKey,
        peer: &StaticPeerConfig,
        sender: u32,
        cookie: Option<&Cookie>,
    ) -> Result<(HandshakeResp, HandshakeState), CryptoError> {
        let hs = &mut self.state;
        let data = &self.message;

        // <- e, ee, se, psk. These DH operations use only the ephemeral private key.
        let epk_r = C::x25519_pubkey(&esk_r.0);
        hs.mix_chain::<C>(&epk_r.0);
        hs.mix_hash::<C>(&epk_r.0);
        hs.mix_edh::<C>(esk_r, &PublicKey(data.ephemeral_key))?;
        hs.mix_edh::<C>(esk_r, &PublicKey(data.static_key.msg))?;
        let k = Zeroizing::new(hs.mix_key_and_hash::<C>(&peer.preshared_key));
        let empty = EncryptedEmpty::encrypt_and_hash::<C>([], hs, &k);

        let mut msg = HandshakeResp {
            _type: little_endian::U32::new(MSG_SECOND),
            sender: little_endian::U32::new(sender),
            receiver: data.sender,
            ephemeral_key: epk_r.0,
            empty,
            mac1: [0; 16],
            mac2: [0; 16],
        };
        msg.mac1 = msg.compute_mac1::<C>(&peer.mac1_key);
        if let Some(cookie) = cookie {
            msg.mac2 = msg.compute_mac2::<C>(cookie);
        }
        Ok((msg, self.state))
    }
}

/// A received response waiting for static/ephemeral DH.
/// Perform admission first. This state owns the response, a transcript snapshot
/// and a zeroizing preshared-key snapshot; waiting borrows no engine or buffers.
#[must_use]
pub struct DecryptHandshakeResp<C> {
    state: HandshakeState,
    message: HandshakeResp,
    preshared_key: Zeroizing<Key>,
    _crypto: PhantomData<fn() -> C>,
}
impl<C: CryptoPrimatives> DecryptHandshakeResp<C> {
    /// Snapshot the outstanding initiation so failed candidate responses do not
    /// consume or corrupt it. Retire it only after a successful, live completion.
    pub fn new(
        message: HandshakeResp,
        state: &HandshakeState,
        peer: &StaticPeerConfig,
        esk_i: &EphemeralPrivateKey,
    ) -> Result<Self, CryptoError> {
        let mut state = state.snapshot();
        let epk_r = PublicKey(message.ephemeral_key);
        state.mix_chain::<C>(&epk_r.0);
        state.mix_hash::<C>(&epk_r.0);
        state.mix_edh::<C>(esk_i, &epk_r)?;
        Ok(Self {
            state,
            message,
            preshared_key: Zeroizing::new(peer.preshared_key),
            _crypto: PhantomData,
        })
    }
    pub fn peer_key(&self) -> PublicKey {
        PublicKey(self.message.ephemeral_key)
    }
    /// Complete with DH using the initiating local static key. Check that the
    /// original handshake remains live before splitting/installing this result.
    pub fn complete(mut self, secret: SharedSecret) -> Result<HandshakeState, CryptoError> {
        self.state.mix_chain::<C>(secret.as_bytes());
        let k = Zeroizing::new(self.state.mix_key_and_hash::<C>(&*self.preshared_key));
        self.message
            .empty
            .decrypt_and_hash::<C>(&mut self.state, &k)?;
        Ok(self.state)
    }
}

impl EphemeralPrivateKey {
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        EphemeralPrivateKey(StaticPrivateKey(b))
    }
}

#[cfg(all(test, any(feature = "graviola", feature = "rustcrypto")))]
mod tests {

    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use tai64::{Tai64, Tai64N};
    use zerocopy::IntoBytes;

    use crate::{
        CookieState, CryptoCore, CryptoPrimatives, DecryptHandshakeInit, DecryptHandshakeResp,
        EncryptHandshakeInit, EphemeralPrivateKey, HandshakeState, HasMac, Key, SharedSecret,
        StaticInitiatorConfig, StaticPeerConfig, StaticPrivateKey,
    };

    fn gen_sk(r: &mut StdRng) -> StaticPrivateKey {
        let mut b = [0u8; 32];
        r.fill_bytes(&mut b);
        StaticPrivateKey(b)
    }

    #[test]
    fn handshake() {
        let mut rng = StdRng::seed_from_u64(3);

        let sk_i = gen_sk(&mut rng);
        let sk_r = gen_sk(&mut rng);
        let mut psk = Key::default();
        rng.fill_bytes(&mut psk);

        let peer_i = StaticPeerConfig::new(CryptoCore::x25519_pubkey(&sk_i), Some(psk), None);
        let peer_r = StaticPeerConfig::new(CryptoCore::x25519_pubkey(&sk_r), Some(psk), None);

        let init_i = StaticInitiatorConfig::new(sk_i);
        let init_r = StaticInitiatorConfig::new(sk_r);

        insta::assert_debug_snapshot!(init_i.mac1_key);
        insta::assert_debug_snapshot!(init_i.cookie_key);

        let now = Tai64N(Tai64(1), 2);

        let cookie_state = CookieState::new(&mut rng);
        let cookie = cookie_state.new_cookie("192.168.1.1:1234".parse().unwrap());

        let esk_i = EphemeralPrivateKey::generate(&mut rng);
        let request = EncryptHandshakeInit::<CryptoCore>::new(
            HandshakeState::default(),
            &init_i.public_key,
            &peer_r,
            &esk_i,
            now,
            1,
            Some(&cookie),
        )
        .unwrap();
        let secret = SharedSecret::new(
            CryptoCore::x25519(&init_i.private_key, &request.peer_key()).unwrap(),
        )
        .unwrap();
        let (init, hs1) = request.complete(secret);

        init.verify_mac1::<CryptoCore>(&init_r.mac1_key).unwrap();
        init.verify_mac2::<CryptoCore>(&cookie).unwrap();

        let request = DecryptHandshakeInit::<CryptoCore>::new(
            init,
            HandshakeState::default(),
            &init_r.public_key,
        );
        let secret = SharedSecret::new(
            CryptoCore::x25519(&init_r.private_key, &request.peer_key()).unwrap(),
        )
        .unwrap();
        let request = request.complete(secret).unwrap();
        let secret = SharedSecret::new(
            CryptoCore::x25519(&init_r.private_key, &request.peer_key()).unwrap(),
        )
        .unwrap();
        let init = request.complete(secret).unwrap();

        assert_eq!(init.static_key().0, peer_i.key.0);
        assert_eq!(init.timestamp(), &now.to_bytes());

        let esk_r = EphemeralPrivateKey::generate(&mut rng);
        let (resp, mut hs2) = init.respond(&esk_r, &peer_i, 2, None).unwrap();

        resp.verify_mac1::<CryptoCore>(&init_i.mac1_key).unwrap();
        insta::assert_debug_snapshot!(resp.empty.as_bytes());

        let request = DecryptHandshakeResp::<CryptoCore>::new(resp, &hs1, &peer_r, &esk_i).unwrap();
        let secret = SharedSecret::new(
            CryptoCore::x25519(&init_i.private_key, &request.peer_key()).unwrap(),
        )
        .unwrap();
        let mut hs1 = request.complete(secret).unwrap();

        let (mut ek1, mut dk1) = hs1.split::<CryptoCore>(true);
        let (mut ek2, mut dk2) = hs2.split::<CryptoCore>(false);

        let mut msg = b"hello world".to_vec();
        let tag = ek1.encrypt::<CryptoCore>(&mut msg);
        insta::assert_debug_snapshot!((&msg, tag.0));
        msg.extend_from_slice(tag.as_bytes());
        let msg = dk2.decrypt::<CryptoCore>(0, &mut msg).unwrap();
        assert_eq!(msg, *b"hello world");

        let mut msg = b"goodbye world".to_vec();
        let tag = ek2.encrypt::<CryptoCore>(&mut msg);
        insta::assert_debug_snapshot!((&msg, tag.0));
        msg.extend_from_slice(tag.as_bytes());
        let msg = dk1.decrypt::<CryptoCore>(0, &mut msg).unwrap();
        assert_eq!(msg, *b"goodbye world");

        let mut msg = b"hello world2".to_vec();
        let tag = ek1.encrypt::<CryptoCore>(&mut msg);
        insta::assert_debug_snapshot!((&msg, tag.0));
        msg.extend_from_slice(tag.as_bytes());
        let msg = dk2.decrypt::<CryptoCore>(1, &mut msg).unwrap();
        assert_eq!(msg, *b"hello world2");

        let mut msg = b"goodbye world2".to_vec();
        let tag = ek2.encrypt::<CryptoCore>(&mut msg);
        insta::assert_debug_snapshot!((&msg, tag.0));
        msg.extend_from_slice(tag.as_bytes());
        let msg = dk1.decrypt::<CryptoCore>(1, &mut msg).unwrap();
        assert_eq!(msg, *b"goodbye world2");
    }

    #[test]
    fn mac_failure() {
        let mut rng = StdRng::seed_from_u64(3);

        let sk_i = gen_sk(&mut rng);
        let sk_r = gen_sk(&mut rng);
        let mut psk = Key::default();
        rng.fill_bytes(&mut psk);

        let peer_r = StaticPeerConfig::new(CryptoCore::x25519_pubkey(&sk_r), Some(psk), None);

        let init_i = StaticInitiatorConfig::new(sk_i);
        let init_r = StaticInitiatorConfig::new(sk_r);

        let now = Tai64N(Tai64(1), 2);

        let cookie_state = CookieState::new(&mut rng);
        let cookie = cookie_state.new_cookie("192.168.1.1:1234".parse().unwrap());

        let esk_i = EphemeralPrivateKey::generate(&mut rng);
        let request = EncryptHandshakeInit::<CryptoCore>::new(
            HandshakeState::default(),
            &init_i.public_key,
            &peer_r,
            &esk_i,
            now,
            1,
            Some(&cookie),
        )
        .unwrap();
        let secret = SharedSecret::new(
            CryptoCore::x25519(&init_i.private_key, &request.peer_key()).unwrap(),
        )
        .unwrap();
        let (mut init, _) = request.complete(secret);

        init.mac2[0] = 0;
        init.verify_mac2::<CryptoCore>(&cookie).unwrap_err();

        init.mac1[0] = 0;
        init.verify_mac1::<CryptoCore>(&init_r.mac1_key)
            .unwrap_err();
    }
}
