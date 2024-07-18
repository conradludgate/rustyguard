#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use core::fmt;
use core::hash::BuildHasher;
use core::net::SocketAddr;
use core::ops::ControlFlow;
use core::time::Duration;

use alloc::collections::BinaryHeap;
use alloc::vec::Vec;

use blake2::digest::generic_array::GenericArray;
use bytemuck::{offset_of, Pod, Zeroable};
use chacha20poly1305::Key;
use chacha20poly1305::{KeyInit, XNonce};
use hashbrown::HashMap;
use hashbrown::HashTable;
use rand::rngs::StdRng;
use rand::CryptoRng;
use rand::{Rng, RngCore, SeedableRng};
use rustc_hash::FxBuildHasher;
use tai64::{Tai64, Tai64N};
pub use utils::Tag;
use utils::{
    hash, mac, Cookie, Encrypted0, Encrypted12, Encrypted32, EncryptedCookie, HandshakeState,
    LEU32, LEU64,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

mod utils;

const REKEY_AFTER_MESSAGES: u64 = 1 << 60; // 2^60
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13); // 2^64 - 2^13 - 1
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Config {
    private_key: StaticSecret,
    public_key: PublicKey,
    mac1_key: Key,
    mac2_key: Key,

    // fx-hash is ok since a third-party cannot
    // insert elements, thus this is hashdos safe.
    // PublicKeys are assumed to be random, thus we
    // would think the hash quality would be decent.
    hasher: FxBuildHasher,
    // hashtable removes the need for the duplicate key inside the peer.
    peers_by_pubkey: HashTable<usize>,

    peers: Vec<Peer>,
}

impl Config {
    pub fn new(private_key: StaticSecret, peers: impl IntoIterator<Item = Peer>) -> Self {
        let peers = peers.into_iter().collect::<Vec<_>>();

        let mut map = HashTable::<usize>::default();
        let hasher = FxBuildHasher;
        for (i, peer) in peers.iter().enumerate() {
            use hashbrown::hash_table::Entry;
            match map.entry(
                hasher.hash_one(peer.key),
                |&i| peers[i].key == peer.key,
                |&i| hasher.hash_one(peers[i].key),
            ) {
                Entry::Occupied(_) => {}
                Entry::Vacant(v) => {
                    v.insert(i);
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
            peers_by_pubkey: map,
            peers,
        }
    }

    fn get_peer_idx(&self, pk: &PublicKey) -> Option<usize> {
        let peers = &self.peers;
        self.peers_by_pubkey
            .find(self.hasher.hash_one(pk), |&i| peers[i].key == *pk)
            .copied()
    }
}

pub struct Peer {
    // static state
    key: PublicKey,
    mac1_key: Key,
    mac2_key: Key,
    preshared_key: Key,

    // dynamic state
    endpoint: Option<SocketAddr>,
    latest_ts: Tai64NBytes,
    cookie: Option<Cookie>,
    handshake: PeerHandshake,
    ciphers: PeerCipherState,
    last_sent_mac1: Mac,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PeerHandshake {
    sent: Tai64N,
    esk_i: StaticSecret,
    state: HandshakeState,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct PeerCipherState {
    sent: Tai64N,
    /// who will the outgoing messages be received by
    receiver: u32,
    /// key to encrypt the outgoing messages
    encrypt: chacha20poly1305::Key,
    /// counter for newly encrypted messages
    nonce: u64,
    /// key to decrypt incoming messages
    decrypt: chacha20poly1305::Key,
}

impl Peer {
    pub fn new(key: PublicKey, preshared_key: Option<Key>, endpoint: Option<SocketAddr>) -> Self {
        Self {
            mac1_key: mac1_key(&key),
            mac2_key: mac2_key(&key),
            key,
            endpoint,
            preshared_key: preshared_key.unwrap_or_default(),
            latest_ts: Tai64NBytes::default(),
            cookie: None,
            handshake: PeerHandshake {
                sent: Tai64N(Tai64(0), 0),
                esk_i: StaticSecret::from([0; 32]),
                state: HandshakeState::default(),
            },
            ciphers: PeerCipherState {
                sent: Tai64N(Tai64(0), 0),
                receiver: Default::default(),
                encrypt: Default::default(),
                nonce: Default::default(),
                decrypt: Default::default(),
            },
            last_sent_mac1: [0; 16],
        }
    }

    fn encrypt_message(&mut self, payload: &mut [u8]) -> Option<(DataHeader, Tag)> {
        use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Nonce};

        let session = &mut self.ciphers;
        if session.sent.0 .0 == 0 {
            return None;
        }

        let n = session.nonce;
        session.nonce += 1;

        let mut nonce = Nonce::default();
        nonce[4..12].copy_from_slice(&n.to_le_bytes());

        let tag = ChaCha20Poly1305::new(&session.encrypt)
            .encrypt_in_place_detached(&nonce, &[], payload)
            .expect("message to large to encrypt");

        let header = DataHeader {
            _type: LEU32::new(MSG_DATA),
            receiver: LEU32::new(session.receiver),
            counter: LEU64::new(n),
        };

        Some((header, Tag::from_tag(tag)))
    }
}

type Tai64NBytes = [u8; 12];

pub struct Sessions {
    config: Config,
    rng: StdRng,
    random_secret: Key,

    last_reseed: Tai64N,
    now: Tai64N,

    // session IDs are chosen randomly by us, thus, are not vulnerable to hashdos
    // and don't need a high-quality hasher
    peers_by_session: HashMap<u32, SessionType, FxBuildHasher>,

    timers: BinaryHeap<TimerEntry>,
}

struct TimerEntry {
    // min-heap by time
    time: Tai64N,
    kind: TimerEntryType,
}
impl PartialEq for TimerEntry {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time
    }
}
impl PartialOrd for TimerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Eq for TimerEntry {}
impl Ord for TimerEntry {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.time.cmp(&other.time).reverse()
    }
}

enum TimerEntryType {
    RekeyAttempt { peer_idx: usize },
    Keepalive { peer_idx: usize },
}

#[derive(Debug)]
enum SessionType {
    Handshake(usize),
    Cipher(usize),
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
            last_reseed: now,
            now,
            rng: StdRng::from_seed(seed),
            peers_by_session: HashMap::default(),
            timers: BinaryHeap::new(),
        }
    }

    /// Should be called at least once per second.
    /// Should be called until it returns None.
    pub fn turn(
        &mut self,
        now: Tai64N,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Option<MaintenanceMsg> {
        if now < self.now {
            return None;
        }
        self.now = now;
        if now.duration_since(&self.last_reseed).unwrap() > Duration::from_secs(120) {
            rng.fill_bytes(&mut self.random_secret[..]);

            let mut seed = <StdRng as rand::SeedableRng>::Seed::default();
            rng.fill_bytes(&mut seed);
            self.rng = StdRng::from_seed(seed);
            self.last_reseed = now;
        }

        while self.timers.peek().is_some_and(|t| t.time < now) {
            let entry = self.timers.pop().unwrap().kind;
            match entry {
                TimerEntryType::RekeyAttempt { peer_idx } => {
                    let peer = &mut self.config.peers[peer_idx];
                    if peer.handshake.sent + REKEY_TIMEOUT < now {
                        return Some(MaintenanceMsg {
                            socket: peer.endpoint.expect("a rekey event should not be scheduled if we've never seen this endpoint before"),
                            data: MaintenanceRepr::Init(HandshakeInit::new(self, peer_idx)),
                        });
                    }
                }
                TimerEntryType::Keepalive { peer_idx } => {
                    let peer = &mut self.config.peers[peer_idx];
                    if peer.ciphers.sent + KEEPALIVE_TIMEOUT < now {
                        let (header, tag) = peer.encrypt_message(&mut []).expect(
                            "a keepalive should only be scheduled if the data keys are set",
                        );
                        peer.ciphers.sent = now;
                        return Some(MaintenanceMsg {
                            socket: peer.endpoint.expect("a keepalive event should not be scheduled if we've never seen this endpoint before"),
                            data: MaintenanceRepr::Data(Keepalive { header, tag }),
                        });
                    }
                }
            }
        }

        None
    }
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
    Read(usize, &'a mut [u8]),
    Noop,
    HandshakeComplete(usize),
}

pub enum SendMessage {
    // This handshake message should be sent
    Maintenance(MaintenanceMsg),
    Data(SocketAddr, DataHeader, utils::Tag),
}

pub struct MaintenanceMsg {
    socket: SocketAddr,
    data: MaintenanceRepr,
}

impl MaintenanceMsg {
    pub fn to(&self) -> SocketAddr {
        self.socket
    }
    pub fn data(&self) -> &[u8] {
        match &self.data {
            MaintenanceRepr::Init(init) => bytemuck::bytes_of(init),
            MaintenanceRepr::Data(ka) => bytemuck::bytes_of(ka),
        }
    }
}

enum MaintenanceRepr {
    Init(HandshakeInit),
    Data(Keepalive),
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct Keepalive {
    header: DataHeader,
    tag: utils::Tag,
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

impl Sessions {
    fn overloaded(&self) -> bool {
        false
    }

    fn cookie(&self, socket: SocketAddr) -> Cookie {
        let ip_bytes = match socket.ip() {
            core::net::IpAddr::V4(ipv4) => &ipv4.octets()[..],
            core::net::IpAddr::V6(ipv6) => &ipv6.octets()[..],
        };
        Cookie(mac(
            &self.random_secret,
            [ip_bytes, &socket.port().to_be_bytes()[..]],
        ))
    }

    pub fn send_message(
        &mut self,
        peer_idx: usize,
        payload: &mut [u8],
    ) -> Result<SendMessage, Error> {
        let peer = &mut self.config.peers.get_mut(peer_idx).ok_or(Error::Rejected)?;
        let Some(ep) = peer.endpoint else {
            return Err(Error::Rejected);
        };
        match peer.encrypt_message(payload) {
            Some((header, tag)) => {
                peer.ciphers.sent = self.now;
                Ok(SendMessage::Data(ep, header, tag))
            }
            None => Ok(SendMessage::Maintenance(MaintenanceMsg {
                socket: ep,
                data: MaintenanceRepr::Init(HandshakeInit::new(self, peer_idx)),
            })),
        }
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
            MSG_DATA => self
                .decrypt_packet(socket, msg)
                .map(|(id, m)| Message::Read(id, m)),
            _ => Err(Error::InvalidMessage),
        }
    }

    #[inline(never)]
    fn handle_handshake_init<'m>(
        &mut self,
        socket: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<&'m mut [u8], Error> {
        let init_msg = match HandshakeInit::verify(msg, self, socket)? {
            ControlFlow::Break(cookie) => {
                // cookie message is always smaller than the initial message
                let cookie_msg = &mut msg[..core::mem::size_of::<CookieMessage>()];
                cookie_msg.copy_from_slice(bytemuck::bytes_of(&cookie));
                return Ok(cookie_msg);
            }
            ControlFlow::Continue(msg) => msg,
        };

        let mut hs = HandshakeState::default();
        let (peer_idx, mut response) = init_msg.process(&mut hs, self)?;
        let peer = &mut self.config.peers[peer_idx];
        peer.endpoint = Some(socket);

        // we are the receiver for now
        let mut receiver = self.rng.gen();
        let vacant = loop {
            use hashbrown::hash_map::Entry;
            match self.peers_by_session.entry(receiver) {
                Entry::Occupied(_) => receiver = self.rng.gen(),
                Entry::Vacant(v) => break v,
            }
        };

        let (initiator, responder) = hs.split();
        peer.ciphers = PeerCipherState {
            sent: self.now,
            receiver: init_msg.sender.get(),
            nonce: 0,
            encrypt: responder,
            decrypt: initiator,
        };

        vacant.insert(SessionType::Cipher(peer_idx));

        response.sender = LEU32::new(receiver);
        response.mac1 = response.compute_mac1(&peer.mac1_key);
        peer.last_sent_mac1 = response.mac1;
        if let Some(cookie) = peer.cookie.as_ref() {
            response.mac2 = response.compute_mac2(cookie);
        }

        // response message is always smaller than the initial message
        let resp_msg = &mut msg[..core::mem::size_of::<HandshakeResp>()];
        resp_msg.copy_from_slice(bytemuck::bytes_of(&response));
        Ok(resp_msg)
    }

    #[inline(never)]
    fn handle_handshake_resp<'m>(
        &mut self,
        socket: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<Message<'m>, Error> {
        let resp_msg = match HandshakeResp::verify(msg, self, socket)? {
            ControlFlow::Break(cookie) => {
                // cookie message is always smaller than the response message
                let cookie_msg = &mut msg[..core::mem::size_of::<CookieMessage>()];
                cookie_msg.copy_from_slice(bytemuck::bytes_of(&cookie));
                return Ok(Message::Write(cookie_msg));
            }
            ControlFlow::Continue(msg) => msg,
        };

        // check for a session expecting this handshake response
        use hashbrown::hash_map::Entry;
        let mut session = match self.peers_by_session.entry(resp_msg.receiver.get()) {
            // session not found
            Entry::Vacant(_) => return Err(Error::Rejected),
            Entry::Occupied(o) => o,
        };
        let peer_idx = match session.get() {
            // session is already past the handshake phase
            SessionType::Cipher(_) => return Err(Error::Rejected),
            SessionType::Handshake(peer_idx) => *peer_idx,
        };
        let peer = &mut self.config.peers[peer_idx];

        resp_msg.process(peer, &self.config.private_key)?;
        peer.endpoint = Some(socket);

        let (initiator, responder) = peer.handshake.state.split();
        peer.handshake.zeroize();

        session.insert(SessionType::Cipher(peer_idx));
        peer.ciphers = PeerCipherState {
            sent: self.now,
            receiver: resp_msg.sender.get(),
            nonce: 0,
            encrypt: initiator,
            decrypt: responder,
        };

        // schedule re-key as we were the initiator
        self.timers.push(TimerEntry {
            time: self.now + REKEY_AFTER_TIME,
            kind: TimerEntryType::RekeyAttempt { peer_idx },
        });

        Ok(Message::HandshakeComplete(peer_idx))
    }

    #[inline(never)]
    fn handle_cookie(&mut self, msg: &mut [u8]) -> Result<(), Error> {
        let cookie_msg = bytemuck::try_from_bytes_mut::<CookieMessage>(msg)
            .map_err(|_| Error::InvalidMessage)?;

        let (SessionType::Cipher(peer_idx) | SessionType::Handshake(peer_idx)) = self
            .peers_by_session
            .get(&cookie_msg.receiver.get())
            .ok_or(Error::Rejected)?;
        let peer = &mut self.config.peers[*peer_idx];

        let cookie = *cookie_msg.cookie.decrypt_cookie(
            &peer.mac2_key,
            (&cookie_msg.nonce).into(),
            &peer.last_sent_mac1,
        )?;

        peer.cookie = Some(cookie);

        Ok(())
    }

    #[inline(never)]
    fn decrypt_packet<'m>(
        &mut self,
        socket: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<(usize, &'m mut [u8]), Error> {
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

        let peer_idx = match self.peers_by_session.get(&header.receiver.get()) {
            Some(SessionType::Handshake(_)) | None => return Err(Error::Rejected),
            Some(SessionType::Cipher(peer_idx)) => *peer_idx,
        };
        let peer = &mut self.config.peers[peer_idx];

        let session = &mut peer.ciphers;
        peer.endpoint = Some(socket);

        if session.sent + KEEPALIVE_TIMEOUT < self.now {
            // schedule the keepalive immediately
            self.timers.push(TimerEntry {
                time: self.now,
                kind: TimerEntryType::Keepalive { peer_idx },
            });
        }

        let mut nonce = Nonce::default();
        nonce[4..12].copy_from_slice(&header.counter.get().to_le_bytes());

        ChaCha20Poly1305::new(&session.decrypt)
            .decrypt_in_place_detached(&nonce, &[], payload, Tag::from_slice(tag))
            .map_err(|_| Error::Rejected)?;

        Ok((peer_idx, payload))
    }
}

#[derive(Pod, Zeroable, Clone, Copy)]
#[repr(C)]
struct CookieMessage {
    _type: LEU32,
    receiver: LEU32,
    nonce: [u8; 24],
    cookie: EncryptedCookie,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct HandshakeInit {
    _type: LEU32,
    sender: LEU32,
    ephemeral_key: [u8; 32],
    static_key: Encrypted32,
    timestamp: Encrypted12,
    mac1: Mac,
    mac2: Mac,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct HandshakeResp {
    _type: LEU32,
    sender: LEU32,
    receiver: LEU32,
    ephemeral_key: [u8; 32],
    empty: Encrypted0,
    mac1: Mac,
    mac2: Mac,
}

type Mac = [u8; 16];

/// Both handshake messages are protected via MACs which can quickly be used
/// to rule out invalid messages.
///
/// The first MAC verifies that the message is even valid - to not waste time.
/// The second MAC is only checked if the server is overloaded. If the server is
/// overloaded and second MAC is invalid, a CookieReply is sent to the client,
/// which contains an encrypted key that can be used to re-sign the handshake later.
trait HasMac: Pod {
    fn verify<'m>(
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
                let cookie = EncryptedCookie::encrypt_cookie(
                    cookie,
                    &state.config.mac2_key,
                    &nonce,
                    this.get_mac1(),
                );

                let msg = CookieMessage {
                    _type: LEU32::new(MSG_COOKIE),
                    receiver: this.sender(),
                    nonce: nonce.into(),
                    cookie,
                };
                return Ok(ControlFlow::Break(msg));
            }
        }

        Ok(ControlFlow::Continue(this))
    }

    fn verify_mac1(&self, config: &Config) -> Result<(), Error> {
        use subtle::ConstantTimeEq;
        let actual_mac1 = self.compute_mac1(&config.mac1_key);
        if actual_mac1.ct_ne(self.get_mac1()).into() {
            Err(Error::Rejected)
        } else {
            Ok(())
        }
    }

    fn verify_mac2(&self, state: &Sessions, socket: SocketAddr) -> Result<(), Cookie> {
        use subtle::ConstantTimeEq;
        let cookie = state.cookie(socket);
        let actual_mac2 = self.compute_mac2(&cookie);
        if actual_mac2.ct_ne(self.get_mac2()).into() {
            Err(cookie)
        } else {
            Ok(())
        }
    }

    fn compute_mac1(&self, mac1_key: &Key) -> Mac;
    fn compute_mac2(&self, cookie: &Cookie) -> Mac;
    fn get_mac1(&self) -> &Mac;
    fn get_mac2(&self) -> &Mac;
    fn sender(&self) -> LEU32;
}

macro_rules! mac_protected {
    ($i:ident, $t:ident) => {
        impl HasMac for $i {
            fn sender(&self) -> LEU32 {
                self.sender
            }

            fn compute_mac1(&self, mac1_key: &Key) -> Mac {
                let offset = offset_of!(self, $i, mac1);
                let bytes = bytemuck::bytes_of(self);
                mac(mac1_key, [&bytes[..offset]])
            }

            fn compute_mac2(&self, cookie: &Cookie) -> Mac {
                let offset = offset_of!(self, $i, mac2);
                let bytes = bytemuck::bytes_of(self);
                mac(&cookie.0, [&bytes[..offset]])
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

fn mac1_key(spk: &PublicKey) -> Key {
    hash([&LABEL_MAC1, spk.as_bytes()])
}
fn mac2_key(spk: &PublicKey) -> Key {
    hash([&LABEL_COOKIE, spk.as_bytes()])
}

impl HandshakeInit {
    #[allow(dead_code)]
    fn new(state: &mut Sessions, peer_idx: usize) -> Self {
        let peer = &mut state.config.peers[peer_idx];

        // we are the receiver for now
        let mut sender = state.rng.gen();
        let vacant = loop {
            use hashbrown::hash_map::Entry;
            match state.peers_by_session.entry(sender) {
                Entry::Occupied(_) => sender = state.rng.gen(),
                Entry::Vacant(v) => break v,
            }
        };
        // peer.session = Some(sender);

        vacant.insert(SessionType::Handshake(peer_idx));
        peer.handshake = PeerHandshake {
            sent: state.now,
            esk_i: StaticSecret::random_from_rng(&mut state.rng),
            state: HandshakeState::default(),
        };
        let ihs = &mut peer.handshake;
        let hs = &mut ihs.state;
        let epk_i = PublicKey::from(&ihs.esk_i);

        hs.mix_hash(peer.key.as_bytes());
        hs.mix_chain(epk_i.as_bytes());
        hs.mix_hash(epk_i.as_bytes());

        let k = hs.mix_key_dh(&ihs.esk_i, &peer.key);
        let spk_i = &state.config.public_key;
        let static_key = Encrypted32::encrypt_and_hash(spk_i.to_bytes(), hs, &k);

        let k = hs.mix_key_dh(&state.config.private_key, &peer.key);
        let timestamp = Encrypted12::encrypt_and_hash(state.now.to_bytes(), hs, &k);

        let mut msg = Self {
            _type: LEU32::new(MSG_FIRST),
            sender: LEU32::new(sender),
            ephemeral_key: epk_i.to_bytes(),
            static_key,
            timestamp,
            mac1: [0; 16],
            mac2: [0; 16],
        };
        msg.mac1 = msg.compute_mac1(&peer.mac1_key);
        peer.last_sent_mac1 = msg.mac1;
        if let Some(cookie) = peer.cookie.as_ref() {
            msg.mac2 = msg.compute_mac2(cookie);
        }

        state.timers.push(TimerEntry {
            time: state.now + REKEY_TIMEOUT,
            kind: TimerEntryType::RekeyAttempt { peer_idx },
        });

        msg
    }

    fn process(
        &mut self,
        hs: &mut HandshakeState,
        state: &mut Sessions,
    ) -> Result<(usize, HandshakeResp), Error> {
        hs.mix_hash(state.config.public_key.as_bytes());
        hs.mix_chain(&self.ephemeral_key);
        hs.mix_hash(&self.ephemeral_key);

        let epk_i = PublicKey::from(self.ephemeral_key);
        let k = hs.mix_key_dh(&state.config.private_key, &epk_i);
        let spk_i = self.static_key.decrypt_and_hash(hs, &k)?;
        let spk_i = PublicKey::from(*spk_i);

        let k = hs.mix_key_dh(&state.config.private_key, &spk_i);
        let timestamp = *self.timestamp.decrypt_and_hash(hs, &k)?;

        // check if we know this peer
        let peer_idx = state.config.get_peer_idx(&spk_i).ok_or(Error::Rejected)?;
        let peer = &mut state.config.peers[peer_idx];

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
        let empty = Encrypted0::encrypt_and_hash([], hs, &k);

        let second = HandshakeResp {
            _type: LEU32::new(MSG_SECOND),
            sender: LEU32::new(0),
            receiver: self.sender,
            ephemeral_key: epk_r.to_bytes(),
            empty,
            mac1: [0; 16],
            mac2: [0; 16],
        };

        Ok((peer_idx, second))
    }
}

impl HandshakeResp {
    fn process(&mut self, peer: &mut Peer, private_key: &StaticSecret) -> Result<(), Error> {
        let hs = &mut peer.handshake.state;
        let epk_r = PublicKey::from(self.ephemeral_key);
        hs.mix_chain(epk_r.as_bytes());
        hs.mix_hash(epk_r.as_bytes());
        hs.mix_dh(&peer.handshake.esk_i, &epk_r);
        hs.mix_dh(private_key, &epk_r);
        let q = &peer.preshared_key;
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
    use chacha20poly1305::Key;
    use rand::{rngs::OsRng, RngCore};
    use tai64::Tai64N;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::{Config, CookieMessage, DataHeader, HandshakeInit, HandshakeResp, Peer, Sessions};

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
        assert_eq!(core::mem::size_of::<HandshakeInit>(), 148);
        assert_eq!(core::mem::align_of::<HandshakeInit>(), 4);

        assert_eq!(core::mem::size_of::<HandshakeResp>(), 92);
        assert_eq!(core::mem::align_of::<HandshakeResp>(), 4);

        assert_eq!(core::mem::size_of::<CookieMessage>(), 64);
        assert_eq!(core::mem::align_of::<CookieMessage>(), 4);

        assert_eq!(core::mem::size_of::<DataHeader>(), 16);
        assert_eq!(core::mem::align_of::<DataHeader>(), 8);

        assert_eq!(core::mem::size_of::<Peer>(), 384);
    }

    fn session_with_peer(
        secret_key: StaticSecret,
        peer_public_key: PublicKey,
        preshared_key: Key,
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
        let m = match sessions_i.send_message(0, &mut msg).unwrap() {
            crate::SendMessage::Maintenance(m) => m,
            crate::SendMessage::Data(_, _, _) => panic!("expecting handshake"),
        };

        // send handshake to server
        let response_buf = {
            let handshake_buf = &mut buf.0[..m.data().len()];
            handshake_buf.copy_from_slice(m.data());
            match sessions_r.recv_message(client_addr, handshake_buf).unwrap() {
                crate::Message::Write(buf) => buf,
                _ => panic!("expecting write"),
            }
        };

        // send the handshake response to the client
        {
            match sessions_i.recv_message(server_addr, response_buf).unwrap() {
                crate::Message::HandshakeComplete(peer_idx) => assert_eq!(peer_idx, 0),
                _ => panic!("expecting noop"),
            };
        }

        // // check the session keys
        // let (_, session_r) = sessions_r.sessions.iter().next().unwrap();
        // let (_, session_i) = sessions_i.sessions.iter().next().unwrap();
        // assert_eq!(session_i.decrypt, session_r.encrypt);
        // assert_eq!(session_i.encrypt, session_r.decrypt);

        // wrap the messasge and encode into buffer
        let data_msg = {
            match sessions_i.send_message(0, &mut msg).unwrap() {
                crate::SendMessage::Maintenance(_msg) => panic!("session should be valid"),
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
                crate::Message::Read(peer_idx, data) => {
                    assert_eq!(peer_idx, 0);
                    assert_eq!(data, b"Hello, World!\0\0\0")
                }
                _ => panic!("expecting read"),
            }
        }
    }
}
