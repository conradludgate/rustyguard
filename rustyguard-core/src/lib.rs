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

use core::net::SocketAddr;
use core::ops::ControlFlow;
use core::time::Duration;
use core::{hash::BuildHasher, net::IpAddr};

use alloc::boxed::Box;
use alloc::collections::BinaryHeap;
use alloc::vec::Vec;

use foldhash::fast::FixedState;
use hashbrown::{HashMap, HashTable};
use rand::{rngs::StdRng, CryptoRng, Rng, RngCore, SeedableRng};
use rustyguard_crypto::{
    decrypt_cookie, decrypt_handshake_init, decrypt_handshake_resp, encrypt_cookie,
    encrypt_handshake_resp, CookieState, CryptoError, DecryptionKey, EncryptionKey, HandshakeState,
    HasMac, Key, Mac, ReusableSecret, StaticInitiatorConfig, StaticPeerConfig,
};
use rustyguard_types::{
    Cookie, CookieMessage, HandshakeInit, HandshakeResp, MSG_COOKIE, MSG_DATA, MSG_FIRST,
    MSG_SECOND,
};
use rustyguard_utils::rate_limiter::CountMinSketch;
use tai64::Tai64;
use zerocopy::{little_endian, AsBytes, FromBytes, FromZeroes};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use rustyguard_crypto::{PublicKey, StaticSecret};
pub use rustyguard_types::DataHeader;
pub use tai64::Tai64N;

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
    static_: StaticInitiatorConfig,

    /// This hashtable identifies peers by their public key.
    ///
    /// The public keys are contained within the `peers` vec.
    /// We use foldhash::fast as the hasher for public-keys. This is considered
    /// safe as this table is immutable (read-only) thus no hash-tampering can take place.
    /// Since public-keys are assumed to be randomly distributed, we can be reasonably
    /// sure that the hash quality is good.
    peers_by_pubkey: HashTable<PeerId>,
    pubkey_hasher: FixedState,

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
        Config {
            static_: StaticInitiatorConfig::new(private_key),
            // TODO(conrad): seed this
            pubkey_hasher: FixedState::with_seed(0),
            peers_by_pubkey: HashTable::default(),
            peers: PeerList(Vec::new()),
        }
    }

    /// Adds a new peer to this wireguard config.
    pub fn insert_peer(&mut self, peer: Peer) -> PeerId {
        use hashbrown::hash_table::Entry;
        match self.peers_by_pubkey.entry(
            self.pubkey_hasher.hash_one(peer.static_.key),
            |&i| self.peers[i].static_.key == peer.static_.key,
            |&i| self.pubkey_hasher.hash_one(self.peers[i].static_.key),
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
            .find(self.pubkey_hasher.hash_one(pk), |&i| {
                peers[i].static_.key == *pk
            })
            .copied()
    }
}

pub struct Peer {
    static_: StaticPeerConfig,

    // dynamic state:
    /// Peer's last known endpoint
    endpoint: Option<SocketAddr>,
    /// Latest handshake init message timestamp sent by the peer.
    latest_ts: Tai64NBytes,
    /// Latest cookie sent by the peer.
    cookie: Option<Cookie>,
    /// Latest mac1 we sent the peer. Needed to decrypt any cookies.
    last_sent_mac1: Mac,

    current_handshake: Option<u32>,
    current_transport: Option<u32>,
}

struct Session {
    peer: PeerId,
    started: Tai64N,
    sent: Tai64N,
    state: SessionState,
}

impl Session {
    fn should_reinit(&self, now: Tai64N, _hs: &SessionHandshake) -> bool {
        (self.sent + REKEY_TIMEOUT < now) && (now < self.started + REKEY_ATTEMPT_TIME)
    }

    fn should_rekey(&self, now: Tai64N, ts: &SessionTransport) -> bool {
        (self.started + REKEY_AFTER_TIME < now) || (ts.encrypt.counter >= REKEY_AFTER_MESSAGES)
    }
    fn should_keepalive(&self, now: Tai64N, _ts: &SessionTransport) -> bool {
        self.sent + KEEPALIVE_TIMEOUT < now
    }
    fn should_reject(&self, now: Tai64N, ts: &SessionTransport) -> bool {
        self.should_expire(now) || (ts.encrypt.counter >= REJECT_AFTER_MESSAGES)
    }
    fn should_expire(&self, now: Tai64N) -> bool {
        self.started + REJECT_AFTER_TIME < now
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "the larger transport state is our expected state"
)]
#[derive(ZeroizeOnDrop)]
enum SessionState {
    Handshake(SessionHandshake),
    Transport(SessionTransport),
}

#[derive(Zeroize)]
struct SessionHandshake {
    esk_i: ReusableSecret,
    state: HandshakeState,
}

#[derive(ZeroizeOnDrop)]
struct SessionTransport {
    /// who will the outgoing messages be received by
    receiver: u32,
    encrypt: EncryptionKey,
    decrypt: DecryptionKey,
}

impl Peer {
    pub fn new(key: PublicKey, preshared_key: Option<Key>, endpoint: Option<SocketAddr>) -> Self {
        Self {
            static_: StaticPeerConfig::new(key, preshared_key),

            endpoint,
            latest_ts: Tai64NBytes::default(),
            cookie: None,
            current_handshake: None,
            current_transport: None,
            last_sent_mac1: [0; 16],
        }
    }

    fn encrypt_message(
        &mut self,
        sessions: &mut SessionMap,
        payload: &mut [u8],
        now: Tai64N,
    ) -> Option<EncryptedMetadata> {
        let session = self.current_transport?;
        let session = sessions.get_mut(&session).unwrap();
        let SessionState::Transport(ts) = &session.state else {
            unreachable!()
        };
        if session.should_reject(now, ts) {
            return None;
        }

        Some(self.force_encrypt(session, payload, now))
    }

    fn force_encrypt(
        &mut self,
        session: &mut Session,
        payload: &mut [u8],
        now: Tai64N,
    ) -> EncryptedMetadata {
        assert_eq!(
            payload.len() % 16,
            0,
            "payload length must be rounded up to the nearest 16 byte boundary"
        );

        let SessionState::Transport(ts) = &mut session.state else {
            unreachable!()
        };
        let n = ts.encrypt.counter;
        let tag = ts.encrypt.encrypt(payload);

        session.sent = now;
        let header = DataHeader {
            _type: little_endian::U32::new(MSG_DATA),
            receiver: little_endian::U32::new(ts.receiver),
            counter: little_endian::U64::new(n),
        };

        EncryptedMetadata {
            header,
            tag,
            payload_len: payload.len(),
        }
    }
}

pub struct MessageEncrypter<'p>(&'p mut Peer, &'p mut Session, Tai64N);

impl MessageEncrypter<'_> {
    pub fn encrypt(self, payload: &mut [u8]) -> EncryptedMetadata {
        self.0.force_encrypt(self.1, payload, self.2)
    }

    /// Encrypts the payload and attaches the wireguard framing in-place.
    ///
    /// The payload is defined to be `buffer[16..buffer.len()-16]`, as first and last
    /// 16 bytes are reserved for the wireguard framing.
    pub fn encrypt_and_frame(self, buffer: &mut [u8]) {
        let len = buffer.len();
        let payload = &mut buffer[16..len - 16];
        self.encrypt(payload).frame_in_place(buffer);
    }
}

type Tai64NBytes = [u8; 12];

// session IDs are chosen randomly by us, thus, are not vulnerable to hashdos
// and don't need a high-quality hasher
type SessionMap = HashMap<u32, Box<Session>, FixedState>;

pub struct Sessions {
    config: Config,
    rng: StdRng,
    cookie: CookieState,

    last_reseed: Tai64N,
    now: Tai64N,

    last_rate_reset: Tai64N,
    ip_rate_limit: CountMinSketch,

    peers_by_session2: SessionMap,

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
    InitAttempt { session_id: u32 },
    RekeyAttempt { session_id: u32 },
    Keepalive { session_id: u32 },
    ExpireTransport { session_id: u32 },
}

impl Sessions {
    pub fn new(config: Config, rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Sessions {
            config,
            cookie: CookieState::default(),
            last_reseed: Tai64N(Tai64(0), 0),
            now: Tai64N(Tai64(0), 0),
            last_rate_reset: Tai64N(Tai64(0), 0),
            ip_rate_limit: CountMinSketch::with_params(10.0 / 20_000.0, 0.01, rng),
            rng: StdRng::from_rng(rng).unwrap(),
            peers_by_session2: HashMap::default(),
            timers: BinaryHeap::new(),
        }
    }

    /// Must be called immediately after new().
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
                self.cookie.generate(rng);

                let mut seed = <StdRng as rand::SeedableRng>::Seed::default();
                rng.fill_bytes(&mut seed);
                self.rng = StdRng::from_seed(seed);
                self.last_reseed = now;
            }
            if now.duration_since(&self.last_rate_reset).unwrap() > Duration::from_secs(1) {
                self.ip_rate_limit.reset();
            }
        }

        while self.timers.peek().is_some_and(|t| t.time < self.now) {
            let entry = self.timers.pop().unwrap().kind;
            match entry {
                TimerEntryType::InitAttempt { session_id }
                | TimerEntryType::RekeyAttempt { session_id } => {
                    let session = self.peers_by_session2.get_mut(&session_id).unwrap();
                    let peer_idx = session.peer;
                    let peer = &mut self.config.peers[peer_idx];

                    // only re-init if
                    // 1. it's been REKEY_TIMEOUT seconds since our last attempt
                    // 2. it's not been more than REKEY_ATTEMPT_TIME seconds since we started
                    // 3. the session needs to be re-init
                    let should_reinit = match &session.state {
                        SessionState::Handshake(hs) => session.should_reinit(self.now, hs),
                        SessionState::Transport(ts) => session.should_rekey(self.now, ts),
                    };

                    if should_reinit {
                        return Some(MaintenanceMsg {
                            socket: peer.endpoint.expect("a rekey event should not be scheduled if we've never seen this endpoint before"),
                            data: MaintenanceRepr::Init(new_handshake(self, peer_idx)),
                        });
                    }
                }
                TimerEntryType::ExpireTransport { session_id } => {
                    let session = self.peers_by_session2.get_mut(&session_id).unwrap();

                    let peer_idx = session.peer;
                    let peer = &mut self.config.peers[peer_idx];

                    if session.should_expire(self.now) {
                        if peer.current_transport == Some(session_id) {
                            peer.current_transport = None;
                        }
                        self.peers_by_session2.remove(&session_id);
                    }
                }
                TimerEntryType::Keepalive { session_id } => {
                    let session = self.peers_by_session2.get_mut(&session_id).unwrap();
                    let peer = &mut self.config.peers[session.peer];

                    let should_keepalive = match &session.state {
                        SessionState::Handshake(_) => false,
                        SessionState::Transport(ts) => session.should_keepalive(self.now, ts),
                    };

                    if should_keepalive {
                        let EncryptedMetadata {
                            header,
                            tag,
                            payload_len: _,
                        } = peer
                            .encrypt_message(&mut self.peers_by_session2, &mut [], self.now)
                            .expect(
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
    DecryptionError,
    Unaligned,
    Rejected,
}

impl From<CryptoError> for Error {
    fn from(value: CryptoError) -> Self {
        match value {
            CryptoError::DecryptionError => Error::DecryptionError,
            CryptoError::Rejected => Error::Rejected,
        }
    }
}

pub enum Message<'a, 's> {
    // This should be sent back to the client
    Write(&'a mut [u8]),
    // This can be processed appropriately
    Read(PeerId, &'a mut [u8]),
    Noop,
    HandshakeComplete(PeerId, MessageEncrypter<'s>),
}

pub enum SendMessage {
    // This handshake message should be sent
    Maintenance(MaintenanceMsg),
    Data(SocketAddr, EncryptedMetadata),
}

pub struct EncryptedMetadata {
    pub header: DataHeader,
    pub tag: rustyguard_types::Tag,
    pub payload_len: usize,
}

impl EncryptedMetadata {
    /// Write the wireguard framing in place for the encrypted data packet.
    /// The data from `buffer[16..16+self.payload_len]` must contain the
    /// encrypted data.
    ///
    /// # Panics
    /// This will panic if the buffer is not correctly sized. It must have space for a 16 byte header and a 16 byte footer.
    pub fn frame_in_place(self, buffer: &mut [u8]) {
        const H: usize = core::mem::size_of::<DataHeader>();
        assert_eq!(self.payload_len + 32, buffer.len());

        buffer[..H].copy_from_slice(self.header.as_bytes());
        buffer[H + self.payload_len..].copy_from_slice(self.tag.as_bytes());
    }
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
            MaintenanceRepr::Init(init) => init.as_bytes(),
            MaintenanceRepr::Data(ka) => ka.as_bytes(),
        }
    }
}

enum MaintenanceRepr {
    Init(HandshakeInit),
    Data(Keepalive),
}

#[derive(Clone, Copy, FromBytes, FromZeroes, AsBytes)]
#[repr(C)]
struct Keepalive {
    header: DataHeader,
    tag: rustyguard_types::Tag,
}

macro_rules! allocate_session {
    ($state:expr) => {{
        let mut session_id = $state.rng.gen();
        loop {
            use hashbrown::hash_map::Entry;
            match $state.peers_by_session2.entry(session_id) {
                Entry::Occupied(_) => session_id = $state.rng.gen(),
                Entry::Vacant(v) => break v,
            }
        }
    }};
}

fn write_msg<'b, T: AsBytes>(buf: &'b mut [u8], t: &T) -> &'b mut [u8] {
    let resp_msg = &mut buf[..core::mem::size_of::<T>()];
    resp_msg.copy_from_slice(t.as_bytes());
    resp_msg
}

impl Sessions {
    fn overloaded(&mut self, ip: IpAddr) -> bool {
        let key = match ip {
            IpAddr::V4(v4) => v4.to_bits() as u64,
            IpAddr::V6(v6) => (v6.to_bits() >> 64) as u64,
        };
        self.ip_rate_limit.count(&key) > 10
    }

    fn write_cookie_message<'b>(
        &mut self,
        mac1: Mac,
        receiver: u32,
        cookie: Cookie,
        buf: &'b mut [u8],
    ) -> &'b mut [u8] {
        // Generating a random nonce and encrypting the cookie takes 1.3us
        // on my M2 Max. Total time to verify the handshake msg is 2.5us.
        // This brings us to 400k handshakes processed per second.
        // As I said above, this should be parallisable with an rng per thread.
        let mut nonce = [0u8; 24];
        self.rng.fill_bytes(&mut nonce);
        let cookie = encrypt_cookie(cookie, &self.config.static_.cookie_key, &nonce, &mac1);

        let msg = CookieMessage {
            _type: little_endian::U32::new(MSG_COOKIE),
            receiver: little_endian::U32::new(receiver),
            nonce,
            cookie,
        };
        write_msg(buf, &msg)
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

        match peer.encrypt_message(&mut self.peers_by_session2, payload, self.now) {
            // we encrypted the message in-place in payload.
            Some(metadata) => {
                let session_id = peer.current_transport.unwrap();
                let session = self.peers_by_session2.get_mut(&session_id).unwrap();
                let SessionState::Transport(ts) = &session.state else {
                    unreachable!()
                };

                if ts.encrypt.counter >= REKEY_AFTER_MESSAGES {
                    // the encryption key needs rotating. schedule a rekey attempt
                    self.timers.push(TimerEntry {
                        time: self.now,
                        kind: TimerEntryType::RekeyAttempt { session_id },
                    });
                }
                Ok(SendMessage::Data(ep, metadata))
            }
            // we could not encrypt the message as we don't yet have an active session.
            // create a handshake init message to be sent.
            None => Ok(SendMessage::Maintenance(MaintenanceMsg {
                socket: ep,
                data: MaintenanceRepr::Init(new_handshake(self, peer_idx)),
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
    pub fn recv_message<'s, 'm>(
        &'s mut self,
        socket: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<Message<'m, 's>, Error> {
        unsafe_log!("[{socket:?}] received packet");

        // For optimisation purposes, we want to assume the message is 16-byte aligned.
        if msg.as_ptr().align_offset(16) != 0 {
            return Err(Error::Unaligned);
        }

        // Every message in wireguard starts with a 1 byte message tag and 3 bytes empty.
        // This happens to be easy to read as a little-endian u32.
        let msg_type = little_endian::U32::ref_from_prefix(msg).ok_or(Error::InvalidMessage)?;
        match msg_type.get() {
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
        addr: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<&'m mut [u8], Error> {
        unsafe_log!("[{addr:?}] parsed as handshake init packet");
        let init_msg = HandshakeInit::mut_from(msg).ok_or(Error::InvalidMessage)?;

        let overload = self.overloaded(addr.ip());
        let init_msg = match HandshakeInit::verify(
            init_msg,
            &self.config.static_,
            overload,
            &self.cookie,
            addr,
        )? {
            // cookie message is always smaller than the initial message
            ControlFlow::Break(cookie) => {
                return Ok(self.write_cookie_message(
                    init_msg.mac1,
                    init_msg.sender.get(),
                    cookie,
                    msg,
                ))
            }
            ControlFlow::Continue(msg) => msg,
        };

        let mut hs = HandshakeState::default();

        let data = decrypt_handshake_init(init_msg, &mut hs, &self.config.static_)?;

        unsafe_log!("payload decrypted");
        // check if we know this peer
        let peer_idx = self
            .config
            .get_peer_idx(&data.static_key())
            .ok_or(Error::Rejected)?;
        let peer = &mut self.config.peers[peer_idx];

        unsafe_log!("peer id: {peer_idx:?}");
        // check for potential replay attack
        if *data.timestamp() < peer.latest_ts {
            return Err(Error::Rejected);
        }
        peer.latest_ts = *data.timestamp();

        // start a new session
        let vacant = allocate_session!(self);
        let session_id = *vacant.key();

        // complete handshake
        let esk_r = StaticSecret::random_from_rng(&mut self.rng);
        let response = encrypt_handshake_resp(
            &mut hs,
            data,
            &esk_r,
            &peer.static_,
            session_id,
            peer.cookie.as_ref(),
        );
        peer.last_sent_mac1 = response.mac1;

        peer.current_transport = Some(session_id);

        // generate the encryption keys
        let (encrypt, decrypt) = hs.split(false);
        let transport = SessionTransport {
            receiver: init_msg.sender.get(),
            encrypt,
            decrypt,
        };
        let session = Session {
            peer: peer_idx,
            started: self.now,
            sent: self.now,
            state: SessionState::Transport(transport),
        };

        vacant.insert(Box::new(session));

        // schedule key expiration
        self.timers.push(TimerEntry {
            time: self.now + REJECT_AFTER_TIME,
            kind: TimerEntryType::ExpireTransport { session_id },
        });

        // response message is always smaller than the initial message
        Ok(write_msg(msg, &response))
    }

    #[inline(never)]
    fn handle_handshake_resp<'s, 'm>(
        &'s mut self,
        addr: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<Message<'m, 's>, Error> {
        unsafe_log!("[{addr:?}] parsed as handshake resp packet");
        let resp_msg = HandshakeResp::mut_from(msg).ok_or(Error::InvalidMessage)?;

        let overload = self.overloaded(addr.ip());
        let resp_msg = match HandshakeResp::verify(
            resp_msg,
            &self.config.static_,
            overload,
            &self.cookie,
            addr,
        )? {
            // cookie message is always smaller than the initial message
            ControlFlow::Break(cookie) => {
                return Ok(Message::Write(self.write_cookie_message(
                    resp_msg.mac1,
                    resp_msg.sender.get(),
                    cookie,
                    msg,
                )))
            }
            ControlFlow::Continue(msg) => msg,
        };

        // check for a session expecting this handshake response
        use hashbrown::hash_map::Entry;
        let session_id = resp_msg.receiver.get();
        let session = match self.peers_by_session2.entry(session_id) {
            // session not found
            Entry::Vacant(_) => {
                unsafe_log!("[{addr:?}] [{session_id:?}] session not found");
                return Err(Error::Rejected);
            }
            Entry::Occupied(o) => o.into_mut(),
        };
        let hs = match &mut session.state {
            // session is already past the handshake phase
            SessionState::Transport(_) => {
                unsafe_log!("[{addr:?}] [{session_id:?}] session handshake already completed");
                return Err(Error::Rejected);
            }
            SessionState::Handshake(hs) => hs,
        };
        let peer = &mut self.config.peers[session.peer];

        decrypt_handshake_resp(
            resp_msg,
            &mut hs.state,
            &self.config.static_,
            &peer.static_,
            &hs.esk_i,
        )?;

        let hs_session = peer.current_handshake.take();
        debug_assert_eq!(hs_session, Some(session_id));
        peer.current_transport = Some(session_id);

        peer.endpoint = Some(addr);

        let (encrypt, decrypt) = hs.state.split(true);
        hs.zeroize();

        session.state = SessionState::Transport(SessionTransport {
            receiver: resp_msg.sender.get(),
            encrypt,
            decrypt,
        });
        session.started = self.now;
        session.sent = self.now;

        // schedule re-key as we were the initiator
        self.timers.push(TimerEntry {
            time: self.now + REKEY_AFTER_TIME,
            kind: TimerEntryType::RekeyAttempt { session_id },
        });
        // schedule key expiration
        self.timers.push(TimerEntry {
            time: self.now + REJECT_AFTER_TIME,
            kind: TimerEntryType::ExpireTransport { session_id },
        });

        Ok(Message::HandshakeComplete(
            session.peer,
            MessageEncrypter(peer, &mut *session, self.now),
        ))
    }

    #[inline(never)]
    fn handle_cookie(&mut self, msg: &mut [u8]) -> Result<(), Error> {
        unsafe_log!("parsed as cookie packet");
        let cookie_msg = CookieMessage::mut_from(msg).ok_or(Error::InvalidMessage)?;

        let session = self
            .peers_by_session2
            .get(&cookie_msg.receiver.get())
            .ok_or(Error::Rejected)?;
        let peer = &mut self.config.peers[session.peer];

        let cookie = decrypt_cookie(
            &mut cookie_msg.cookie,
            &peer.static_.cookie_key,
            &cookie_msg.nonce,
            &peer.last_sent_mac1,
        )?;

        peer.cookie = Some(*cookie);

        Ok(())
    }

    #[inline(never)]
    fn decrypt_packet<'m>(
        &mut self,
        socket: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<(PeerId, &'m mut [u8]), Error> {
        unsafe_log!("[{socket:?}] parsed as data packet");

        let (header, payload, tag) =
            DataHeader::message_mut_from(msg).ok_or(Error::InvalidMessage)?;

        let session_id = header.receiver.get();
        let Some(session) = self.peers_by_session2.get_mut(&session_id) else {
            unsafe_log!("[{socket:?}] [{session_id:?}] session not ready");
            return Err(Error::Rejected);
        };
        let ts = match &mut session.state {
            SessionState::Handshake(_) => {
                unsafe_log!("[{socket:?}] [{session_id:?}] session not ready");
                return Err(Error::Rejected);
            }
            SessionState::Transport(ts) => ts,
        };
        let peer = &mut self.config.peers[session.peer];
        peer.endpoint = Some(socket);

        if session.sent + KEEPALIVE_TIMEOUT < self.now {
            // schedule the keepalive immediately
            self.timers.push(TimerEntry {
                time: self.now,
                kind: TimerEntryType::Keepalive { session_id },
            });
        }

        let payload = payload.as_bytes_mut();
        ts.decrypt.decrypt(header.counter.get(), payload, tag)?;

        Ok((session.peer, payload))
    }
}

fn new_handshake(state: &mut Sessions, peer_idx: PeerId) -> HandshakeInit {
    let peer = &mut state.config.peers[peer_idx];

    let old_handshake = peer
        .current_handshake
        .and_then(|session| state.peers_by_session2.remove(&session));

    // start a new session
    let vacant = allocate_session!(state);
    let sender = *vacant.key();
    peer.current_handshake = Some(sender);

    let handshake = SessionHandshake {
        esk_i: ReusableSecret::random_from_rng(&mut state.rng),
        state: HandshakeState::default(),
    };

    let session = match old_handshake {
        Some(mut session) => {
            session.sent = state.now;
            session.state = SessionState::Handshake(handshake);
            session
        }
        None => Box::new(Session {
            peer: peer_idx,
            started: state.now,
            sent: state.now,
            state: SessionState::Handshake(handshake),
        }),
    };

    let session_id = *vacant.key();
    let session = vacant.insert(session);
    let SessionState::Handshake(handshake) = &mut session.state else {
        unreachable!()
    };

    let msg = rustyguard_crypto::encrypt_handshake_init(
        &mut handshake.state,
        &state.config.static_,
        &peer.static_,
        &handshake.esk_i,
        state.now,
        sender,
        peer.cookie.as_ref(),
    );

    state.timers.push(TimerEntry {
        time: state.now + REKEY_TIMEOUT,
        kind: TimerEntryType::InitAttempt { session_id },
    });

    msg
}

#[cfg(test)]
mod tests {
    use core::net::SocketAddr;

    use crate::{PublicKey, StaticSecret};
    use alloc::boxed::Box;
    use rand::{
        rngs::{OsRng, StdRng},
        RngCore, SeedableRng,
    };
    use rustyguard_crypto::Key;
    use tai64::Tai64N;
    use zerocopy::AsBytes;

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
        let mut session = Sessions::new(config, &mut OsRng);
        session.turn(Tai64N::now(), &mut OsRng);
        (id, session)
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
            crate::SendMessage::Data(_, _) => panic!("expecting handshake"),
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
        let encryptor = {
            match sessions_i.recv_message(server_addr, response_buf).unwrap() {
                crate::Message::HandshakeComplete(peer_idx, encryptor) => {
                    assert_eq!(peer_idx, peer_i);
                    encryptor
                }
                _ => panic!("expecting noop"),
            }
        };

        // wrap the messasge and encode into buffer
        let data_msg = {
            let metadata = encryptor.encrypt(&mut msg);
            buf.0[..16].copy_from_slice(metadata.header.as_bytes());
            buf.0[16..32].copy_from_slice(&msg);
            buf.0[32..48].copy_from_slice(&metadata.tag.0);
            &mut buf.0[..48]
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
        let mut sessions_i = Sessions::new(config, &mut rng);
        sessions_i.turn(now, &mut rng);

        let peer = Peer::new(spk_i, Some(psk), Some(client_addr));
        let mut config = Config::new(ssk_r);
        let peer_i = config.insert_peer(peer);
        let mut sessions_r = Sessions::new(config, &mut rng);
        sessions_r.turn(now, &mut rng);

        let mut buf = Box::new(AlignedPacket([0; 256]));

        let mut msg = *b"Hello, World!\0\0\0";

        // try wrap the message - get back handshake message to send
        let m = match sessions_i.send_message(peer_r, &mut msg).unwrap() {
            crate::SendMessage::Maintenance(m) => m,
            crate::SendMessage::Data(_, _) => panic!("expecting handshake"),
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
        let encryptor = {
            match sessions_i.recv_message(server_addr, response_buf).unwrap() {
                crate::Message::HandshakeComplete(peer_idx, encryptor) => {
                    assert_eq!(peer_idx, peer_i);
                    encryptor
                }
                _ => panic!("expecting noop"),
            }
        };

        // wrap the messasge and encode into buffer
        let data_msg = {
            let metadata = encryptor.encrypt(&mut msg);
            buf.0[..16].copy_from_slice(metadata.header.as_bytes());
            buf.0[16..32].copy_from_slice(&msg);
            buf.0[32..48].copy_from_slice(&metadata.tag.0);
            &mut buf.0[..48]
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
