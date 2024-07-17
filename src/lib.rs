#![no_std]

extern crate alloc;

use core::fmt;
use core::hash::BuildHasher;
use core::net::SocketAddr;
use core::num::NonZeroU32;
use core::ops::ControlFlow;
use core::time::Duration;

use alloc::boxed::Box;

use blake2::digest::consts::{U0, U12, U16, U32};
use blake2::digest::generic_array::GenericArray;
use bytemuck::{offset_of, Pod, Zeroable};
use chacha20poly1305::{KeyInit, Tag, XNonce};
use hashbrown::HashMap;
use hashbrown::HashTable;
use rand::rngs::StdRng;
use rand::CryptoRng;
use rand::{Rng, RngCore, SeedableRng};
use rustc_hash::FxBuildHasher;
use tai64::Tai64N;
use utils::{hash, mac, Bytes, Encrypted, HandshakeState, LEU32, LEU64};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

mod utils;

const REKEY_AFTER_MESSAGES: u64 = 1 << 60; // 2^60
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - 1 << 13; // 2^64 - 2^13 - 1
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Config {
    private_key: StaticSecret,
    public_key: PublicKey,
    mac1_key: GenericArray<u8, U32>,
    mac2_key: GenericArray<u8, U32>,
    // fx-hash is ok since a third-party cannot
    // insert elements, thus this is hashdos safe.
    // PublicKeys are assumed to be random, thus we
    // would think the hash quality would be decent.
    hasher: FxBuildHasher,
    // hashtable removes the need for the duplicate key inside the peer.
    peers: HashTable<Peer>,
}

impl Config {
    pub fn new(private_key: StaticSecret, peers: impl IntoIterator<Item = Peer>) -> Self {
        let mut map = HashTable::<Peer>::default();
        let hasher = FxBuildHasher;
        for peer in peers {
            use hashbrown::hash_table::Entry;
            match map.entry(
                hasher.hash_one(peer.key),
                |p| p.key == peer.key,
                |p| hasher.hash_one(p.key),
            ) {
                Entry::Occupied(_) => {}
                Entry::Vacant(v) => {
                    v.insert(peer);
                }
            }
        }

        let public_key = PublicKey::from(&private_key);

        Config {
            mac1_key: mac1_key(&public_key),
            mac2_key: mac2_key(&public_key),
            private_key,
            public_key,
            hasher,
            peers: map,
        }
    }

    fn get_peer(&self, pk: &PublicKey) -> Option<&Peer> {
        self.peers.find(self.hasher.hash_one(pk), |p| p.key == *pk)
    }

    fn get_peer_mut(&mut self, pk: &PublicKey) -> Option<&mut Peer> {
        self.peers
            .find_mut(self.hasher.hash_one(pk), |p| p.key == *pk)
    }
}

#[derive(Debug)]
pub struct Peer {
    // static state
    key: PublicKey,
    mac1_key: GenericArray<u8, U32>,
    mac2_key: GenericArray<u8, U32>,
    // ips: Vec<IpNet>,
    endpoint: Option<SocketAddr>,
    preshared_key: GenericArray<u8, U32>,

    // dynamic state
    latest_ts: Tai64NBytes,
    cookie: Option<GenericArray<u8, U16>>,
    session: Option<NonZeroU32>,
}

impl Peer {
    pub fn new(
        key: PublicKey,
        preshared_key: Option<GenericArray<u8, U32>>,
        endpoint: Option<SocketAddr>,
    ) -> Self {
        Self {
            mac1_key: mac1_key(&key),
            mac2_key: mac2_key(&key),
            key,
            endpoint,
            preshared_key: preshared_key.unwrap_or_default(),
            latest_ts: Tai64NBytes::default(),
            cookie: None,
            session: None,
        }
    }
}

type Tai64NBytes = GenericArray<u8, U12>;

pub struct Sessions {
    config: Config,
    rng: StdRng,
    random_secret: GenericArray<u8, U32>,

    now: Tai64N,

    // session IDs are chosen randomly, and not by external users,
    // thus, are not vulnerable to hashdos and don't need a high-quality hasher
    sessions: HashMap<NonZeroU32, Box<CipherState>, FxBuildHasher>,
    handshakes: HashMap<NonZeroU32, Box<InitiatedHandshakes>, FxBuildHasher>,
    // virtual_ips: HashMap<SocketAddr, >
    // endpoints:
}

impl Sessions {
    pub fn new(config: Config, now: Tai64N, rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut random_secret = GenericArray::default();
        rng.fill_bytes(&mut random_secret[..]);

        let mut seed = <StdRng as rand::SeedableRng>::Seed::default();
        rng.fill_bytes(&mut seed);

        Sessions {
            config,
            random_secret,
            now,
            rng: StdRng::from_seed(seed),
            sessions: HashMap::default(),
            handshakes: HashMap::default(),
        }
    }

    /// Must be called every 120 seconds
    pub fn reseed(&mut self, rng: &mut (impl CryptoRng + RngCore)) {
        rng.fill_bytes(&mut self.random_secret[..]);

        let mut seed = <StdRng as rand::SeedableRng>::Seed::default();
        rng.fill_bytes(&mut seed);
        self.rng = StdRng::from_seed(seed);
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct InitiatedHandshakes {
    mac1: GenericArray<u8, U16>,
    peer_key: PublicKey,
    esk_i: StaticSecret,
    preshared_key: GenericArray<u8, U32>,
    state: HandshakeState,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct CipherState {
    mac1: GenericArray<u8, U16>,
    peer_key: PublicKey,
    /// who will the outgoing messages be received by
    receiver: u32,
    /// key to encrypt the outgoing messages
    encrypt: chacha20poly1305::Key,
    /// counter for newly encrypted messages
    nonce: u64,
    /// key to decrypt incoming messages
    decrypt: chacha20poly1305::Key,
}

#[derive(Debug)]
pub enum Error {
    InvalidMessage,
    Unspecified,
    Unaligned,
    Rejected,
}

#[derive(Clone, Copy, Hash, PartialEq, PartialOrd)]
pub struct SessionId(u32);

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:16X}", self.0)
    }
}

pub enum Message<'a> {
    // This should be sent back to the client
    Write(&'a mut [u8]),
    // This can be processed appropriately
    Read(PublicKey, &'a mut [u8]),
    Noop,
    HandshakeComplete(PublicKey),
}

pub enum SendMessage {
    // This handshake message should be sent
    Maintenance(MaintenanceMsg),
    Data(Option<SocketAddr>, DataHeader, Tag),
}

pub struct MaintenanceMsg(HandshakeRepr);

impl AsRef<[u8]> for MaintenanceMsg {
    fn as_ref(&self) -> &[u8] {
        match &self.0 {
            HandshakeRepr::Init(init) => bytemuck::bytes_of(init),
        }
    }
}

enum HandshakeRepr {
    Init(MacProtected<FirstMessage>),
}

const MSG_FIRST: u32 = 1;
const MSG_SECOND: u32 = 2;
const MSG_DATA: u32 = 4;
const MSG_COOKIE: u32 = 3;

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

type Cookie = GenericArray<u8, U16>;

impl Sessions {
    fn overloaded(&self) -> bool {
        false
    }

    fn cookie(&self, socket: SocketAddr) -> Cookie {
        let ip_bytes = match socket.ip() {
            core::net::IpAddr::V4(ipv4) => &ipv4.octets()[..],
            core::net::IpAddr::V6(ipv6) => &ipv6.octets()[..],
        };
        mac(
            &self.random_secret,
            [ip_bytes, &socket.port().to_be_bytes()[..]],
        )
    }

    pub fn send_message(
        &mut self,
        pk: &PublicKey,
        payload: &mut [u8],
    ) -> Result<SendMessage, Error> {
        use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Nonce};

        let peer = self.config.get_peer(pk).ok_or(Error::Rejected)?;
        let Some(session) = peer.session.and_then(|s| self.sessions.get_mut(&s)) else {
            return Ok(SendMessage::Maintenance(MaintenanceMsg(
                HandshakeRepr::Init(FirstMessage::new(self, pk)),
            )));
        };

        let n = session.nonce;
        session.nonce += 1;

        let mut nonce = Nonce::default();
        nonce[4..12].copy_from_slice(&n.to_le_bytes());

        let tag = ChaCha20Poly1305::new(&session.encrypt)
            .encrypt_in_place_detached(&nonce, &[], payload)
            .map_err(|_| Error::Rejected)?;

        let header = DataHeader {
            _type: LEU32::new(MSG_DATA),
            receiver: LEU32::new(session.receiver),
            counter: LEU64::new(n),
        };

        Ok(SendMessage::Data(peer.endpoint, header, tag))
    }

    /// Given a packet, and the socket addr it was received from,
    /// it will be parsed, processed, decrypted and the payload returned.
    ///
    /// The buffer the packet is contained within must be 16-byte aligned.
    ///
    /// # Returns
    ///
    /// * [`Message::Noop`] - The packet was ok, but there is nothing to do right now
    /// * [`Message::Read`] - The packet was a data packet, the data is decrypted and ready to be read
    /// * [`Message::Write`] - This is a new packet that must be sent back.
    ///
    /// # Errors
    ///
    /// * Any invalid messages will be reported as [`Error::InvalidMessage`].
    /// * Any valid messages that could not be decrypted or processed will be reported as [`Error::Rejected`]
    ///
    // TODO(conrad): enforce the msg is 16 byte aligned.
    pub fn recv_message<'m>(
        &mut self,
        socket: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<Message<'m>, Error> {
        if msg.as_ptr().align_offset(16) != 0 {
            return Err(Error::Unaligned);
        }

        let (msg_type, _) = msg.split_first_chunk_mut().ok_or(Error::InvalidMessage)?;
        match u32::from_le_bytes(*msg_type) {
            MSG_FIRST => self.handle_handshake_init(socket, msg).map(Message::Write),
            MSG_SECOND => self.handle_handshake_resp(socket, msg),
            MSG_COOKIE => self.handle_cookie(msg).map(|_| Message::Noop),
            MSG_DATA => self.decrypt_packet(msg).map(|(id, m)| Message::Read(id, m)),
            _ => Err(Error::InvalidMessage),
        }
    }

    #[inline(never)]
    fn handle_handshake_init<'m>(
        &mut self,
        socket: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<&'m mut [u8], Error> {
        let (sender, first_message) = match MacProtected::<FirstMessage>::verify(msg, self, socket)?
        {
            ControlFlow::Break(cookie) => {
                // cookie message is always smaller than the initial message
                let cookie_msg = &mut msg[..core::mem::size_of::<CookieMessage>()];
                cookie_msg.copy_from_slice(bytemuck::bytes_of(&cookie));
                return Ok(cookie_msg);
            }
            ControlFlow::Continue(MacProtected { sender, inner, .. }) => (*sender, inner),
        };

        let mut hs = HandshakeState::default();
        let (peer, response) = first_message.process(&mut hs, sender, self)?;
        peer.endpoint = Some(socket);
        let peer_key = peer.key;
        let cookie = peer.cookie;
        let mac1_key = peer.mac1_key;

        // we are the receiver for now
        let mut receiver = self.rng.gen();
        let vacant = loop {
            use hashbrown::hash_map::Entry;
            match self.sessions.entry(receiver) {
                Entry::Occupied(_) => receiver = self.rng.gen(),
                Entry::Vacant(v) => break v,
            }
        };

        self.config
            .get_peer_mut(&peer_key)
            .ok_or(Error::Rejected)?
            .session = Some(receiver);

        let resp = MacProtected::new(
            LEU32::new(MSG_SECOND),
            LEU32::new(receiver.get()),
            response,
            cookie.as_ref(),
            &mac1_key,
        );

        let (initiator, responder) = hs.split();
        vacant.insert(Box::new(CipherState {
            mac1: resp.mac1.0,
            peer_key,
            // messages we send will be received by the client who sent the current message.
            receiver: sender.get(),
            nonce: 0,
            encrypt: responder,
            decrypt: initiator,
        }));

        // response message is always smaller than the initial message
        let resp_msg = &mut msg[..core::mem::size_of::<MacProtected<SecondMessage>>()];
        resp_msg.copy_from_slice(bytemuck::bytes_of(&resp));
        Ok(resp_msg)
    }

    #[inline(never)]
    fn handle_handshake_resp<'m>(
        &mut self,
        socket: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<Message<'m>, Error> {
        let (sender, second_message) =
            match MacProtected::<SecondMessage>::verify(msg, self, socket)? {
                ControlFlow::Break(cookie) => {
                    // cookie message is always smaller than the response message
                    let cookie_msg = &mut msg[..core::mem::size_of::<CookieMessage>()];
                    cookie_msg.copy_from_slice(bytemuck::bytes_of(&cookie));
                    return Ok(Message::Write(cookie_msg));
                }
                ControlFlow::Continue(MacProtected { sender, inner, .. }) => (*sender, inner),
            };

        // check for a session expecting this handshake response
        let receiver = NonZeroU32::new(second_message.receiver.get()).ok_or(Error::Rejected)?;
        let mut ihs = self.handshakes.remove(&receiver).ok_or(Error::Rejected)?;

        second_message.process(&mut ihs, &self.config)?;

        let (initiator, responder) = ihs.state.split();
        self.sessions.insert(
            receiver,
            Box::new(CipherState {
                mac1: ihs.mac1,
                peer_key: ihs.peer_key,
                receiver: sender.get(),
                nonce: 0,
                encrypt: initiator,
                decrypt: responder,
            }),
        );

        Ok(Message::HandshakeComplete(ihs.peer_key))
    }

    #[inline(never)]
    fn handle_cookie(&mut self, msg: &mut [u8]) -> Result<(), Error> {
        let cookie_msg = bytemuck::try_from_bytes_mut::<CookieMessage>(msg)
            .map_err(|_| Error::InvalidMessage)?;

        let receiver = NonZeroU32::new(cookie_msg.receiver.get()).ok_or(Error::Rejected)?;
        let (mac1, peer_key) = if let Some(ihs) = self.handshakes.get(&receiver) {
            (ihs.mac1, ihs.peer_key)
        } else if let Some(cs) = self.sessions.get(&receiver) {
            (cs.mac1, cs.peer_key)
        } else {
            return Err(Error::Rejected);
        };

        let peer = self.config.get_peer_mut(&peer_key).ok_or(Error::Rejected)?;

        let cookie =
            *cookie_msg
                .cookie
                .decrypt_cookie(&peer.mac2_key, &cookie_msg.nonce.0, &mac1)?;

        peer.cookie = Some(cookie);

        Ok(())
    }

    #[inline(never)]
    fn decrypt_packet<'m>(
        &mut self,
        msg: &'m mut [u8],
    ) -> Result<(PublicKey, &'m mut [u8]), Error> {
        use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Nonce, Tag};
        const HEADER_LEN: usize = core::mem::size_of::<DataHeader>();

        if msg.as_ptr().align_offset(16) != 0 {
            return Err(Error::Unaligned);
        }

        if msg.len() % 16 != 0 || msg.len() < HEADER_LEN + 16 {
            return Err(Error::InvalidMessage);
        }

        let (header, payload) = msg
            .split_first_chunk_mut::<HEADER_LEN>()
            .ok_or(Error::InvalidMessage)?;
        let (payload, tag) = payload
            .split_last_chunk_mut::<16>()
            .ok_or(Error::InvalidMessage)?;

        let header: &mut DataHeader =
            bytemuck::try_from_bytes_mut(header).map_err(|_| Error::InvalidMessage)?;

        let receiver = NonZeroU32::new(header.receiver.get()).ok_or(Error::Rejected)?;
        let session = self.sessions.get_mut(&receiver).ok_or(Error::Rejected)?;

        let mut nonce = Nonce::default();
        nonce[4..12].copy_from_slice(&header.counter.get().to_le_bytes());

        ChaCha20Poly1305::new(&session.decrypt)
            .decrypt_in_place_detached(&nonce, &[], payload, Tag::from_slice(tag))
            .map_err(|_| Error::Rejected)?;

        Ok((session.peer_key, payload))
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
    _type: LEU32,
    receiver: LEU32,
    nonce: Bytes<chacha20poly1305::consts::U24>,
    cookie: Encrypted<U16>,
}

/// Both handshake messages are protected via MACs which can quickly be used
/// to rule out invalid messages.
///
/// The first MAC verifies that the message is even valid - to not waste time.
/// The second MAC is only checked if the server is overloaded. If the server is
/// overloaded and second MAC is invalid, a CookieReply is sent to the client,
/// which contains an encrypted key that can be used to re-sign the handshake later.
#[derive(Clone, Copy)]
#[repr(C)]
struct MacProtected<T> {
    _type: LEU32,
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
        _type: LEU32,
        sender: LEU32,
        msg: T,
        cookie: Option<&GenericArray<u8, U16>>,
        mac1_key: &GenericArray<u8, U32>,
    ) -> Self {
        let mut mac = Self {
            _type,
            sender,
            inner: msg,
            mac1: Bytes(GenericArray::default()),
            mac2: Bytes(GenericArray::default()),
        };
        mac.mac1.0 = mac.mac1(mac1_key);
        if let Some(cookie) = cookie {
            mac.mac2.0 = mac.mac2(cookie);
        }
        mac
    }

    pub fn verify<'m>(
        msg: &'m mut [u8],
        state: &mut Sessions,
        socket: SocketAddr,
    ) -> Result<ControlFlow<CookieMessage, &'m mut Self>, Error> {
        let this: &'m mut Self =
            bytemuck::try_from_bytes_mut(msg).map_err(|_| Error::InvalidMessage)?;

        this.verify_mac1(&state.config)?;
        if state.overloaded() {
            if let Err(cookie) = this.verify_mac2(state, socket) {
                let mut nonce = XNonce::default();
                state.rng.fill_bytes(&mut nonce);
                let cookie =
                    Encrypted::encrypt_cookie(cookie, &state.config.mac2_key, &nonce, &this.mac1.0);

                let msg = CookieMessage {
                    _type: LEU32::new(MSG_COOKIE),
                    receiver: this.sender,
                    nonce: Bytes(nonce),
                    cookie,
                };
                return Ok(ControlFlow::Break(msg));
            }
        }

        Ok(ControlFlow::Continue(this))
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

    fn verify_mac2(&self, state: &Sessions, socket: SocketAddr) -> Result<(), Cookie> {
        use subtle::ConstantTimeEq;
        let cookie = state.cookie(socket);
        let actual_mac2 = self.mac2(&cookie);
        if actual_mac2.ct_ne(&self.mac2.0).into() {
            Err(cookie)
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
    #[allow(dead_code)]
    fn new(state: &mut Sessions, to: &PublicKey) -> MacProtected<Self> {
        let peer = state
            .config
            .peers
            .find_mut(state.config.hasher.hash_one(to), |p| p.key == *to)
            .expect("peer should not be missing");

        // we are the receiver for now
        let mut sender = state.rng.gen();
        let vacant = loop {
            use hashbrown::hash_map::Entry;
            if state.sessions.contains_key(&sender) {
                sender = state.rng.gen()
            } else {
                match state.handshakes.entry(sender) {
                    Entry::Occupied(_) => sender = state.rng.gen(),
                    Entry::Vacant(v) => break v,
                }
            }
        };
        peer.session = Some(sender);
        let ihs = vacant.insert(Box::new(InitiatedHandshakes {
            mac1: GenericArray::default(),
            peer_key: peer.key,
            esk_i: StaticSecret::random_from_rng(&mut state.rng),
            preshared_key: peer.preshared_key,
            state: HandshakeState::default(),
        }));
        let hs = &mut ihs.state;
        let esk_i = &ihs.esk_i;
        let epk_i = PublicKey::from(esk_i);

        hs.mix_hash(peer.key.as_bytes());
        hs.mix_chain(epk_i.as_bytes());
        hs.mix_hash(epk_i.as_bytes());

        let k = hs.mix_key_dh(esk_i, &peer.key);
        let spk_i = &state.config.public_key;
        let static_key = GenericArray::from(spk_i.to_bytes());
        let static_key = Encrypted::encrypt_and_hash(static_key, hs, &k);

        let k = hs.mix_key_dh(&state.config.private_key, &peer.key);
        let timestamp = GenericArray::from(state.now.to_bytes());
        let timestamp = Encrypted::encrypt_and_hash(timestamp, hs, &k);

        let this = Self {
            ephemeral_key: epk_i.to_bytes(),
            static_key,
            timestamp,
        };

        let msg = MacProtected::new(
            LEU32::new(MSG_FIRST),
            LEU32::new(sender.get()),
            this,
            None,
            &mac1_key(&peer.key),
        );
        ihs.mac1 = msg.mac1.0;

        msg
    }

    fn process<'c>(
        &mut self,
        hs: &mut HandshakeState,
        sender: LEU32,
        state: &'c mut Sessions,
    ) -> Result<(&'c mut Peer, SecondMessage), Error> {
        hs.mix_hash(state.config.public_key.as_bytes());
        hs.mix_chain(&self.ephemeral_key);
        hs.mix_hash(&self.ephemeral_key);

        let epk_i = PublicKey::from(self.ephemeral_key);
        let k = hs.mix_key_dh(&state.config.private_key, &epk_i);
        let spk_i = self.static_key.decrypt_and_hash(hs, &k)?;
        let spk_i = PublicKey::from(<[u8; 32]>::from(*spk_i));

        let k = hs.mix_key_dh(&state.config.private_key, &spk_i);
        let timestamp = *self.timestamp.decrypt_and_hash(hs, &k)?;

        // check if we know this peer
        let peer = state.config.get_peer_mut(&spk_i).ok_or(Error::Rejected)?;

        // check for potential replay attack
        if timestamp < peer.latest_ts {
            return Err(Error::Rejected);
        }

        peer.latest_ts = timestamp;

        let esk_r = StaticSecret::random_from_rng(&mut state.rng);
        let epk_r = PublicKey::from(&esk_r);
        hs.mix_chain(epk_r.as_bytes());
        hs.mix_hash(epk_r.as_bytes());
        hs.mix_dh(&esk_r, &epk_i);
        hs.mix_dh(&esk_r, &spk_i);
        let q = peer.preshared_key;
        let k = hs.mix_key2(&q);
        let empty = Encrypted::encrypt_and_hash(GenericArray::<u8, U0>::default(), hs, &k);

        let second = SecondMessage {
            receiver: sender,
            ephemeral_key: epk_r.to_bytes(),
            empty,
        };

        Ok((peer, second))
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
    fn process(&mut self, ihs: &mut InitiatedHandshakes, config: &Config) -> Result<(), Error> {
        let hs = &mut ihs.state;
        let epk_r = PublicKey::from(self.ephemeral_key);
        hs.mix_chain(epk_r.as_bytes());
        hs.mix_hash(epk_r.as_bytes());
        hs.mix_dh(&ihs.esk_i, &epk_r);
        hs.mix_dh(&config.private_key, &epk_r);
        let q = &ihs.preshared_key;
        let k = hs.mix_key2(q);
        self.empty.decrypt_and_hash(hs, &k)?;

        Ok(())
    }
}

#[derive(Pod, Zeroable, Clone, Copy)]
#[repr(C)]
pub struct DataHeader {
    _type: LEU32,
    receiver: LEU32,
    counter: LEU64,
}

impl AsRef<[u8]> for DataHeader {
    fn as_ref(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }
}

#[cfg(test)]
mod tests {
    use core::net::SocketAddr;

    use alloc::boxed::Box;
    use blake2::{digest::generic_array::GenericArray, Digest};
    use chacha20poly1305::consts::U32;
    use rand::{rngs::OsRng, RngCore};
    use tai64::Tai64N;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::{
        Config, CookieMessage, DataHeader, FirstMessage, MacProtected, Peer, SecondMessage,
        Sessions,
    };

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
        assert_eq!(core::mem::size_of::<MacProtected<FirstMessage>>(), 148);
        assert_eq!(core::mem::align_of::<MacProtected<FirstMessage>>(), 4);

        assert_eq!(core::mem::size_of::<MacProtected<SecondMessage>>(), 92);
        assert_eq!(core::mem::align_of::<MacProtected<SecondMessage>>(), 4);

        assert_eq!(core::mem::size_of::<CookieMessage>(), 64);
        assert_eq!(core::mem::align_of::<CookieMessage>(), 4);

        assert_eq!(core::mem::size_of::<DataHeader>(), 16);
        assert_eq!(core::mem::align_of::<DataHeader>(), 8);
    }

    fn session_with_peer(
        secret_key: StaticSecret,
        peer_public_key: PublicKey,
        preshared_key: GenericArray<u8, U32>,
    ) -> Sessions {
        let peer = Peer::new(peer_public_key, Some(preshared_key), None);
        let config = Config::new(secret_key, [peer]);
        Sessions::new(config, Tai64N::now(), &mut OsRng)
    }

    #[repr(align(16))]
    struct AlignedPacket([u8; 256]);

    #[test]
    fn handshake_happy() {
        let server_addr: SocketAddr = "10.0.1.1:1234".parse().unwrap();
        let client_addr: SocketAddr = "10.0.2.1:1234".parse().unwrap();
        let ssk_i = StaticSecret::random_from_rng(OsRng);
        let ssk_r = StaticSecret::random_from_rng(OsRng);
        let spk_i = PublicKey::from(&ssk_i);
        let spk_r = PublicKey::from(&ssk_r);
        let mut psk = GenericArray::default();
        OsRng.fill_bytes(&mut psk);

        let mut sessions_i = session_with_peer(ssk_i, spk_r, psk);
        let mut sessions_r = session_with_peer(ssk_r, spk_i, psk);

        let mut buf = Box::new(AlignedPacket([0; 256]));

        let mut msg = *b"Hello, World!\0\0\0";

        // try wrap the message - get back handshake message to send
        let m = match sessions_i.send_message(&spk_r, &mut msg).unwrap() {
            crate::SendMessage::Maintenance(m) => m,
            crate::SendMessage::Data(_, _, _) => panic!("expecting handshake"),
        };

        // send handshake to server
        let response_buf = {
            let handshake_buf = &mut buf.0[..m.as_ref().len()];
            handshake_buf.copy_from_slice(m.as_ref());
            match sessions_r.recv_message(client_addr, handshake_buf).unwrap() {
                crate::Message::Write(buf) => buf,
                _ => panic!("expecting write"),
            }
        };

        // send the handshake response to the client
        {
            match sessions_i.recv_message(server_addr, response_buf).unwrap() {
                crate::Message::HandshakeComplete(pk) => assert_eq!(pk, spk_r),
                _ => panic!("expecting noop"),
            };
        }

        // check the session keys
        let (_, session_r) = sessions_r.sessions.iter().next().unwrap();
        let (_, session_i) = sessions_i.sessions.iter().next().unwrap();
        assert_eq!(session_i.decrypt, session_r.encrypt);
        assert_eq!(session_i.encrypt, session_r.decrypt);

        // wrap the messasge and encode into buffer
        let data_msg = {
            match sessions_i.send_message(&spk_r, &mut msg).unwrap() {
                crate::SendMessage::Maintenance(_) => panic!("session should be valid"),
                crate::SendMessage::Data(_socket, header, tag) => {
                    // assert_eq!(socket, Some(server_addr));

                    buf.0[..16].copy_from_slice(header.as_ref());
                    buf.0[16..32].copy_from_slice(&msg);
                    buf.0[32..48].copy_from_slice(&tag);
                    &mut buf.0[..48]
                }
            }
        };

        // send the buffer to the server
        {
            match sessions_r.recv_message(client_addr, data_msg).unwrap() {
                crate::Message::Read(pk, data) => {
                    assert_eq!(pk, spk_i);
                    assert_eq!(data, b"Hello, World!\0\0\0")
                }
                _ => panic!("expecting read"),
            }
        }
    }
}
