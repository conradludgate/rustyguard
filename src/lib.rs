#![no_std]
#![forbid(unsafe_code)]

#[cfg(any(test, rustyguard_unsafe_logging))]
extern crate std;

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

extern crate alloc;

use core::hash::BuildHasher;
use core::net::SocketAddr;
use core::ops::ControlFlow;
use core::time::Duration;

use alloc::collections::BinaryHeap;
use alloc::vec::Vec;

use bytemuck::{Pod, Zeroable};
use crypto::{
    cookie_key, mac, mac1_key, Cookie, DecryptionKey, EncryptionKey, HandshakeState, Key, Mac, Tag,
};
use hashbrown::{HashMap, HashTable};
use messages::{
    CookieMessage, HandshakeInit, HandshakeResp, HasMac, LEU32, LEU64, MSG_COOKIE, MSG_DATA,
    MSG_FIRST, MSG_SECOND,
};
use rand::{rngs::StdRng, CryptoRng, Rng, RngCore, SeedableRng};
use rustc_hash::FxBuildHasher;
use tai64::{Tai64, Tai64N};
pub use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

mod crypto;
mod messages;

pub use messages::DataHeader;

/// After sending this many messages, a rekey should take place.
const REKEY_AFTER_MESSAGES: u64 = 1 << 60; // 2^60
/// After sending this many messages, a rekey must take place.
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13); // 2^64 - 2^13 - 1
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(u32);

impl core::fmt::Debug for PeerId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PeerId({:08X})", &self.0)
    }
}
impl PeerId {
    pub const fn sentinal() -> Self {
        Self(u32::MAX)
    }
}

pub struct Config {
    /// Our private key
    private_key: StaticSecret,
    /// Cached public key, derived from the above private key
    public_key: PublicKey,
    /// Cached mac1_key: calculated using `mac1_key(&self.public_key)`
    mac1_key: Key,
    /// Cached cookie_key: calculated using `cookie_key(&self.public_key)`
    cookie_key: Key,

    /// This hashtable identifies peers by their public key.
    ///
    /// The public keys are contained within the `peers` vec.
    /// We use FxHasher as the hasher for public-keys. This is considered
    /// safe as this table is immutable (read-only) thus no hash-tampering can take place.
    /// Since public-keys are assumed to be randomly distributed, we can be reasonably
    /// sure that the hash quality is good.
    peers_by_pubkey: HashTable<PeerId>,

    /// List of peers that this wireguard server can talk to.
    peers: PeerList,
}

struct PeerList(Vec<Peer>);
impl core::ops::Index<PeerId> for PeerList {
    type Output = Peer;

    fn index(&self, index: PeerId) -> &Self::Output {
        &self.0[index.0 as usize]
    }
}
impl core::ops::IndexMut<PeerId> for PeerList {
    fn index_mut(&mut self, index: PeerId) -> &mut Self::Output {
        &mut self.0[index.0 as usize]
    }
}
impl PeerList {
    fn get_mut(&mut self, index: PeerId) -> Option<&mut Peer> {
        self.0.get_mut(index.0 as usize)
    }
}

impl Config {
    pub fn new(private_key: StaticSecret) -> Self {
        let public_key = PublicKey::from(&private_key);

        Config {
            mac1_key: mac1_key(&public_key),
            cookie_key: cookie_key(&public_key),
            private_key,
            public_key,
            peers_by_pubkey: HashTable::default(),
            peers: PeerList(Vec::new()),
        }
    }

    /// Adds a new peer to this wireguard config.
    pub fn insert_peer(&mut self, peer: Peer) -> PeerId {
        use hashbrown::hash_table::Entry;
        match self.peers_by_pubkey.entry(
            FxBuildHasher.hash_one(peer.key),
            |&i| self.peers[i].key == peer.key,
            |&i| FxBuildHasher.hash_one(self.peers[i].key),
        ) {
            Entry::Occupied(o) => {
                let id = *o.get();

                self.peers[id] = peer;

                id
            }
            Entry::Vacant(v) => {
                let idx = self.peers.0.len();
                let id = PeerId(idx as u32);

                self.peers.0.push(peer);
                v.insert(id);

                id
            }
        }
    }

    fn get_peer_idx(&self, pk: &PublicKey) -> Option<PeerId> {
        let peers = &self.peers;
        self.peers_by_pubkey
            .find(FxBuildHasher.hash_one(pk), |&i| peers[i].key == *pk)
            .copied()
    }
}

pub struct Peer {
    // static state
    /// Peer's public key.
    key: PublicKey,
    /// Peer's preshared key.
    preshared_key: Key,
    /// Cached mac1_key: calculated using `mac1_key(&self.key)`
    mac1_key: Key,
    /// Cached cookie_key: calculated using `cookie_key(&self.key)`
    cookie_key: Key,

    // dynamic state:
    /// Peer's last known endpoint
    endpoint: Option<SocketAddr>,
    /// Latest handshake init message timestamp sent by the peer.
    latest_ts: Tai64NBytes,
    /// Latest cookie sent by the peer.
    cookie: Option<Cookie>,
    /// Latest mac1 we sent the peer. Needed to decrypt any cookies.
    last_sent_mac1: Mac,

    /// The inflight handshake. Only set by the initiator of a session
    handshake: PeerHandshake,
    // TODO(conrad): handle previous transport keys too
    /// The current inflight transport keys used to decrypt
    transport: PeerCipherState,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PeerHandshake {
    started: Tai64N,
    sent: Tai64N,
    esk_i: StaticSecret,
    state: HandshakeState,
}

#[derive(ZeroizeOnDrop)]
struct PeerCipherState {
    started: Tai64N,
    sent: Tai64N,
    /// who will the outgoing messages be received by
    receiver: u32,
    encrypt: EncryptionKey,
    decrypt: DecryptionKey,
}

impl PeerHandshake {
    fn should_reinit(&self, now: Tai64N) -> bool {
        (self.sent + REKEY_TIMEOUT < now) && (now < self.started + REKEY_ATTEMPT_TIME)
    }
}
impl PeerCipherState {
    fn should_rekey(&self, now: Tai64N) -> bool {
        (self.started + REKEY_AFTER_TIME < now) || (self.encrypt.counter >= REKEY_AFTER_MESSAGES)
    }
    fn should_keepalive(&self, now: Tai64N) -> bool {
        self.sent + KEEPALIVE_TIMEOUT < now
    }
    fn should_reject(&self, now: Tai64N) -> bool {
        (self.started == Tai64N(Tai64(0), 0))
            || (self.started + REJECT_AFTER_TIME < now)
            || (self.encrypt.counter >= REJECT_AFTER_MESSAGES)
    }
}

impl Peer {
    pub fn new(key: PublicKey, preshared_key: Option<Key>, endpoint: Option<SocketAddr>) -> Self {
        Self {
            mac1_key: mac1_key(&key),
            cookie_key: cookie_key(&key),
            key,
            endpoint,
            preshared_key: preshared_key.unwrap_or_default(),
            latest_ts: Tai64NBytes::default(),
            cookie: None,
            handshake: PeerHandshake {
                started: Tai64N(Tai64(0), 0),
                sent: Tai64N(Tai64(0), 0),
                esk_i: StaticSecret::from([0; 32]),
                state: HandshakeState::default(),
            },
            transport: PeerCipherState {
                started: Tai64N(Tai64(0), 0),
                sent: Tai64N(Tai64(0), 0),
                receiver: Default::default(),
                encrypt: EncryptionKey::new(Default::default()),
                decrypt: DecryptionKey::new(Default::default()),
            },
            last_sent_mac1: [0; 16],
        }
    }

    fn encrypt_message(&mut self, payload: &mut [u8], now: Tai64N) -> Option<(DataHeader, Tag)> {
        let session = &mut self.transport;
        if session.should_reject(now) {
            return None;
        }

        let n = session.encrypt.counter;
        let tag = session.encrypt.encrypt(payload);

        session.sent = now;
        let header = DataHeader {
            _type: LEU32::new(MSG_DATA),
            receiver: LEU32::new(session.receiver),
            counter: LEU64::new(n),
        };

        Some((header, tag))
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

#[derive(Debug)]
enum TimerEntryType {
    InitAttempt { peer_idx: PeerId },
    RekeyAttempt { peer_idx: PeerId },
    Keepalive { peer_idx: PeerId },
}

#[derive(Debug)]
enum SessionType {
    Handshake(PeerId),
    Cipher(PeerId),
}

impl Sessions {
    pub fn new(config: Config, now: Tai64N, rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut random_secret = Key::default();
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
        if now > self.now {
            self.now = now;
            if now.duration_since(&self.last_reseed).unwrap() > Duration::from_secs(120) {
                rng.fill_bytes(&mut self.random_secret[..]);

                let mut seed = <StdRng as rand::SeedableRng>::Seed::default();
                rng.fill_bytes(&mut seed);
                self.rng = StdRng::from_seed(seed);
                self.last_reseed = now;
            }
        }

        while self.timers.peek().is_some_and(|t| t.time < self.now) {
            let entry = self.timers.pop().unwrap().kind;
            match entry {
                TimerEntryType::InitAttempt { peer_idx } => {
                    let peer = &mut self.config.peers[peer_idx];
                    // only re-init if
                    // 1. it's been REKEY_TIMEOUT seconds since our last attempt
                    // 2. it's not been more than REKEY_ATTEMPT_TIME seconds since we started
                    // 3. the session needs to be re-init
                    if peer.handshake.should_reinit(self.now)
                        && peer.transport.should_rekey(self.now)
                    {
                        return Some(MaintenanceMsg {
                            socket: peer.endpoint.expect("a rekey event should not be scheduled if we've never seen this endpoint before"),
                            data: MaintenanceRepr::Init(HandshakeInit::new(self, peer_idx)),
                        });
                    }
                }
                TimerEntryType::RekeyAttempt { peer_idx } => {
                    let peer = &mut self.config.peers[peer_idx];
                    if peer.transport.should_rekey(self.now) {
                        return Some(MaintenanceMsg {
                            socket: peer.endpoint.expect("a rekey event should not be scheduled if we've never seen this endpoint before"),
                            data: MaintenanceRepr::Init(HandshakeInit::new(self, peer_idx)),
                        });
                    }
                }
                TimerEntryType::Keepalive { peer_idx } => {
                    let peer = &mut self.config.peers[peer_idx];
                    if peer.transport.should_keepalive(self.now) {
                        let (header, tag) = peer.encrypt_message(&mut [], self.now).expect(
                            "a keepalive should only be scheduled if the data keys are set",
                        );
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

pub enum Message<'a> {
    // This should be sent back to the client
    Write(&'a mut [u8]),
    // This can be processed appropriately
    Read(PeerId, &'a mut [u8]),
    Noop,
    HandshakeComplete(PeerId),
}

pub enum SendMessage {
    // This handshake message should be sent
    Maintenance(MaintenanceMsg),
    Data(SocketAddr, DataHeader, crypto::Tag),
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
    tag: crypto::Tag,
}

macro_rules! allocate_session {
    ($state:expr) => {{
        let mut session_id = $state.rng.gen();
        loop {
            use hashbrown::hash_map::Entry;
            match $state.peers_by_session.entry(session_id) {
                Entry::Occupied(_) => session_id = $state.rng.gen(),
                Entry::Vacant(v) => break v,
            }
        }
    }};
}

fn write_msg<'b, T: Pod>(buf: &'b mut [u8], t: &T) -> &'b mut [u8] {
    let resp_msg = &mut buf[..core::mem::size_of::<T>()];
    resp_msg.copy_from_slice(bytemuck::bytes_of(t));
    resp_msg
}

impl Sessions {
    fn overloaded(&self) -> bool {
        false
    }

    fn cookie(&self, socket: SocketAddr) -> Cookie {
        // there's no specified encoding here - it just needs to contain the IP address and port :shrug:
        let mut a = [0; 20];
        match socket.ip() {
            core::net::IpAddr::V4(ipv4) => a[..4].copy_from_slice(&ipv4.octets()[..]),
            core::net::IpAddr::V6(ipv6) => a[..16].copy_from_slice(&ipv6.octets()[..]),
        }
        a[16..].copy_from_slice(&socket.port().to_le_bytes()[..]);
        Cookie(mac(&self.random_secret, &a))
    }

    pub fn send_message(
        &mut self,
        peer_idx: PeerId,
        payload: &mut [u8],
    ) -> Result<SendMessage, Error> {
        let peer = self.config.peers.get_mut(peer_idx).ok_or(Error::Rejected)?;
        let Some(ep) = peer.endpoint else {
            return Err(Error::Rejected);
        };

        match peer.encrypt_message(payload, self.now) {
            // we encrypted the message in-place in payload.
            Some((header, tag)) => {
                if peer.transport.encrypt.counter >= REKEY_AFTER_MESSAGES {
                    // the encryption key needs rotating. schedule a rekey attempt
                    self.timers.push(TimerEntry {
                        time: self.now,
                        kind: TimerEntryType::RekeyAttempt { peer_idx },
                    });
                }
                Ok(SendMessage::Data(ep, header, tag))
            }
            // we could not encrypt the message as we don't yet have an active session.
            // create a handshake init message to be sent.
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
        unsafe_log!("[{socket:?}] received packet");

        // For optimisation purposes, we want to assume the message is 16-byte aligned.
        if msg.as_ptr().align_offset(16) != 0 {
            return Err(Error::Unaligned);
        }

        // Every message in wireguard starts with a 1 byte message tag and 3 bytes empty.
        // This happens to be easy to read as a little-endian u32.
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
        unsafe_log!("[{socket:?}] parsed as handshake init packet");
        let init_msg = match HandshakeInit::verify(msg, self, socket)? {
            // cookie message is always smaller than the initial message
            ControlFlow::Break(cookie) => return Ok(write_msg(msg, &cookie)),
            ControlFlow::Continue(msg) => msg,
        };

        let mut hs = HandshakeState::default();

        let data = init_msg.decrypt(&mut hs, &self.config)?;

        unsafe_log!("payload decrypted");
        // check if we know this peer
        let peer_idx = self
            .config
            .get_peer_idx(&data.spk_i)
            .ok_or(Error::Rejected)?;
        let peer = &mut self.config.peers[peer_idx];

        unsafe_log!("peer id: {peer_idx:?}");
        // check for potential replay attack
        if data.timestamp < peer.latest_ts {
            return Err(Error::Rejected);
        }
        peer.latest_ts = data.timestamp;

        // start a new session
        let vacant = allocate_session!(self);

        // complete handshake
        let esk_r = StaticSecret::random_from_rng(&mut self.rng);
        let response = HandshakeResp::encrypt_for(&mut hs, &data, &esk_r, peer, *vacant.key());

        // generate the encryption keys
        let (initiator, responder) = hs.split();
        peer.transport = PeerCipherState {
            started: self.now,
            sent: self.now,
            receiver: init_msg.sender.get(),
            encrypt: EncryptionKey::new(responder),
            decrypt: DecryptionKey::new(initiator),
        };

        vacant.insert(SessionType::Cipher(peer_idx));

        // response message is always smaller than the initial message
        Ok(write_msg(msg, &response))
    }

    #[inline(never)]
    fn handle_handshake_resp<'m>(
        &mut self,
        socket: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<Message<'m>, Error> {
        unsafe_log!("[{socket:?}] parsed as handshake resp packet");
        let resp_msg = match HandshakeResp::verify(msg, self, socket)? {
            // cookie message is always smaller than the initial message
            ControlFlow::Break(cookie) => return Ok(Message::Write(write_msg(msg, &cookie))),
            ControlFlow::Continue(msg) => msg,
        };

        // check for a session expecting this handshake response
        use hashbrown::hash_map::Entry;
        let session_id = resp_msg.receiver.get();
        let mut session = match self.peers_by_session.entry(session_id) {
            // session not found
            Entry::Vacant(_) => {
                unsafe_log!("[{socket:?}] [{session_id:?}] session not found");
                return Err(Error::Rejected);
            }
            Entry::Occupied(o) => o,
        };
        let peer_idx = match session.get() {
            // session is already past the handshake phase
            SessionType::Cipher(_) => {
                unsafe_log!("[{socket:?}] [{session_id:?}] session handshake already completed");
                return Err(Error::Rejected);
            }
            SessionType::Handshake(peer_idx) => *peer_idx,
        };
        let peer = &mut self.config.peers[peer_idx];

        resp_msg.decrypt(peer, &self.config.private_key)?;
        peer.endpoint = Some(socket);

        let (initiator, responder) = peer.handshake.state.split();
        peer.handshake.zeroize();

        session.insert(SessionType::Cipher(peer_idx));
        peer.transport = PeerCipherState {
            started: self.now,
            sent: self.now,
            receiver: resp_msg.sender.get(),
            encrypt: EncryptionKey::new(initiator),
            decrypt: DecryptionKey::new(responder),
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
        unsafe_log!("parsed as cookie packet");
        let cookie_msg = bytemuck::try_from_bytes_mut::<CookieMessage>(msg)
            .map_err(|_| Error::InvalidMessage)?;

        let (SessionType::Cipher(peer_idx) | SessionType::Handshake(peer_idx)) = self
            .peers_by_session
            .get(&cookie_msg.receiver.get())
            .ok_or(Error::Rejected)?;
        let peer = &mut self.config.peers[*peer_idx];

        let cookie = *cookie_msg.cookie.decrypt_cookie(
            &peer.cookie_key,
            &cookie_msg.nonce,
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
    ) -> Result<(PeerId, &'m mut [u8]), Error> {
        const HEADER_LEN: usize = core::mem::size_of::<DataHeader>();

        unsafe_log!("[{socket:?}] parsed as data packet");

        if msg.as_ptr().align_offset(16) != 0 {
            return Err(Error::Unaligned);
        }

        if msg.len() % 16 != 0 || msg.len() < HEADER_LEN + 16 {
            unsafe_log!("[{socket:?}] msg wrong size: len={}", msg.len());
            return Err(Error::InvalidMessage);
        }

        let (header, payload) = msg
            .split_first_chunk_mut::<HEADER_LEN>()
            .ok_or(Error::InvalidMessage)?;
        let (payload, tag) = payload
            .split_last_chunk_mut::<16>()
            .ok_or(Error::InvalidMessage)?;

        let header: &mut DataHeader = bytemuck::cast_mut::<[u8; HEADER_LEN], DataHeader>(header);

        let session_id = header.receiver.get();
        let peer_idx = match self.peers_by_session.get(&session_id) {
            Some(SessionType::Handshake(_)) | None => {
                unsafe_log!("[{socket:?}] [{session_id:?}] session not ready");
                return Err(Error::Rejected);
            }
            Some(SessionType::Cipher(peer_idx)) => *peer_idx,
        };
        let peer = &mut self.config.peers[peer_idx];

        let session = &mut peer.transport;
        peer.endpoint = Some(socket);

        if session.sent + KEEPALIVE_TIMEOUT < self.now {
            // schedule the keepalive immediately
            self.timers.push(TimerEntry {
                time: self.now,
                kind: TimerEntryType::Keepalive { peer_idx },
            });
        }

        session
            .decrypt
            .decrypt(header.counter.get(), payload, Tag::from_slice(tag))?;

        Ok((peer_idx, payload))
    }
}

impl HandshakeInit {
    #[allow(dead_code)]
    fn new(state: &mut Sessions, peer_idx: PeerId) -> Self {
        let peer = &mut state.config.peers[peer_idx];

        // start a new session
        let vacant = allocate_session!(state);
        let sender = *vacant.key();

        vacant.insert(SessionType::Handshake(peer_idx));
        peer.handshake = PeerHandshake {
            started: peer.handshake.started,
            sent: state.now,
            esk_i: StaticSecret::random_from_rng(&mut state.rng),
            state: HandshakeState::default(),
        };

        let msg = Self::encrypt_for(
            &state.config.private_key,
            &state.config.public_key,
            peer,
            sender,
        );

        state.timers.push(TimerEntry {
            time: state.now + REKEY_TIMEOUT,
            kind: TimerEntryType::InitAttempt { peer_idx },
        });

        msg
    }
}

#[cfg(test)]
mod tests {
    use core::net::SocketAddr;

    use alloc::boxed::Box;
    use chacha20poly1305::Key;
    use rand::{
        rngs::{OsRng, StdRng},
        RngCore, SeedableRng,
    };
    use tai64::Tai64N;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::{Config, Peer, PeerId, Sessions};

    fn session_with_peer(
        secret_key: StaticSecret,
        peer_public_key: PublicKey,
        preshared_key: Key,
        endpoint: SocketAddr,
    ) -> (PeerId, Sessions) {
        let peer = Peer::new(peer_public_key, Some(preshared_key), Some(endpoint));
        let mut config = Config::new(secret_key);
        let id = config.insert_peer(peer);
        (id, Sessions::new(config, Tai64N::now(), &mut OsRng))
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
        let mut psk = Key::default();
        OsRng.fill_bytes(&mut psk);

        let (peer_r, mut sessions_i) = session_with_peer(ssk_i, spk_r, psk, server_addr);
        let (peer_i, mut sessions_r) = session_with_peer(ssk_r, spk_i, psk, client_addr);

        let mut buf = Box::new(AlignedPacket([0; 256]));

        let mut msg = *b"Hello, World!\0\0\0";

        // try wrap the message - get back handshake message to send
        let m = match sessions_i.send_message(peer_r, &mut msg).unwrap() {
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
                crate::Message::HandshakeComplete(peer_idx) => assert_eq!(peer_idx, peer_i),
                _ => panic!("expecting noop"),
            };
        }

        // wrap the messasge and encode into buffer
        let data_msg = {
            match sessions_i.send_message(peer_r, &mut msg).unwrap() {
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
                    assert_eq!(peer_idx, peer_i);
                    assert_eq!(data, b"Hello, World!\0\0\0")
                }
                _ => panic!("expecting read"),
            }
        }
    }

    #[test]
    fn snapshot() {
        let mut rng = StdRng::seed_from_u64(1);
        let server_addr: SocketAddr = "10.0.1.1:1234".parse().unwrap();
        let client_addr: SocketAddr = "10.0.2.1:1234".parse().unwrap();
        let ssk_i = StaticSecret::random_from_rng(&mut rng);
        let ssk_r = StaticSecret::random_from_rng(&mut rng);
        let spk_i = PublicKey::from(&ssk_i);
        let spk_r = PublicKey::from(&ssk_r);
        let mut psk = Key::default();
        rng.fill_bytes(&mut psk);

        let now = Tai64N::UNIX_EPOCH;

        let peer = Peer::new(spk_r, Some(psk), Some(server_addr));
        let mut config = Config::new(ssk_i);
        let peer_r = config.insert_peer(peer);
        let mut sessions_i = Sessions::new(config, now, &mut rng);

        let peer = Peer::new(spk_i, Some(psk), Some(client_addr));
        let mut config = Config::new(ssk_r);
        let peer_i = config.insert_peer(peer);
        let mut sessions_r = Sessions::new(config, now, &mut rng);

        let mut buf = Box::new(AlignedPacket([0; 256]));

        let mut msg = *b"Hello, World!\0\0\0";

        // try wrap the message - get back handshake message to send
        let m = match sessions_i.send_message(peer_r, &mut msg).unwrap() {
            crate::SendMessage::Maintenance(m) => m,
            crate::SendMessage::Data(_, _, _) => panic!("expecting handshake"),
        };

        insta::assert_debug_snapshot!(m.data());

        // send handshake to server
        let response_buf = {
            let handshake_buf = &mut buf.0[..m.data().len()];
            handshake_buf.copy_from_slice(m.data());
            match sessions_r.recv_message(client_addr, handshake_buf).unwrap() {
                crate::Message::Write(buf) => buf,
                _ => panic!("expecting write"),
            }
        };

        insta::assert_debug_snapshot!(response_buf);

        // send the handshake response to the client
        {
            match sessions_i.recv_message(server_addr, response_buf).unwrap() {
                crate::Message::HandshakeComplete(peer_idx) => assert_eq!(peer_idx, peer_i),
                _ => panic!("expecting noop"),
            };
        }

        // wrap the messasge and encode into buffer
        let data_msg = {
            match sessions_i.send_message(peer_r, &mut msg).unwrap() {
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

        insta::assert_debug_snapshot!(data_msg);

        // send the buffer to the server
        {
            match sessions_r.recv_message(client_addr, data_msg).unwrap() {
                crate::Message::Read(peer_idx, data) => {
                    assert_eq!(peer_idx, peer_i);
                    assert_eq!(data, b"Hello, World!\0\0\0")
                }
                _ => panic!("expecting read"),
            }
        }
    }
}
