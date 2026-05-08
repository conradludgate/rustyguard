#![no_std]
#![forbid(unsafe_code)]

#[cfg(any(test, rustyguard_unsafe_logging))]
extern crate std;

/// Internal debug-trace macro. The output is "unsafe" because it can leak
/// secrets, peer ids, addresses, and other privacy-sensitive data — never
/// enable it in production.
///
/// It is a no-op unless one of the following is true:
/// * the crate is built under `cfg(test)`, or
/// * the consumer sets `--cfg rustyguard_unsafe_logging` (allowed via the
///   `unexpected_cfgs` lints config in this crate's Cargo.toml).
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

use core::cell::RefCell;
use core::net::SocketAddr;
use core::time::Duration;
use core::{hash::BuildHasher, net::IpAddr};

use alloc::boxed::Box;
use alloc::collections::BinaryHeap;
use alloc::vec::Vec;

use foldhash::fast::FixedState;
use handshake::new_handshake;
use hashbrown::{HashMap, HashTable};
use rand_chacha::ChaCha12Rng as StdRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use rustyguard_crypto::{
    encrypt_cookie, CookieState, CryptoCore, CryptoError, DecryptionKey, DhOracle, EncryptionKey,
    EphemeralPrivateKey, HandshakeState, Mac, StaticInitiatorConfig, StaticPeerConfig,
};
use rustyguard_types::{
    Cookie, CookieMessage, HandshakeInit, MSG_COOKIE, MSG_DATA, MSG_FIRST, MSG_SECOND,
};
use rustyguard_utils::rate_limiter::CountMinSketch;
use tai64::Tai64;
use time::{TimerEntry, TimerEntryType};
use zerocopy::{little_endian, FromBytes, Immutable, IntoBytes, KnownLayout};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use rustyguard_crypto::{PublicKey, StaticPrivateKey};
pub use rustyguard_types::DataHeader;
pub use tai64::Tai64N;

mod handshake;
mod time;

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

pub struct Config<O = StaticPrivateKey> {
    static_: StaticInitiatorConfig<O>,

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
    peers: PeerList<StaticPeerConfig>,
}

struct PeerList<P>(Vec<P>);
impl<P> core::ops::Index<PeerId> for PeerList<P> {
    type Output = P;

    fn index(&self, index: PeerId) -> &Self::Output {
        &self.0[index.0 as usize]
    }
}
impl<P> core::ops::IndexMut<PeerId> for PeerList<P> {
    fn index_mut(&mut self, index: PeerId) -> &mut Self::Output {
        &mut self.0[index.0 as usize]
    }
}
impl<P> PeerList<P> {
    fn get_mut(&mut self, index: PeerId) -> Option<&mut P> {
        self.0.get_mut(index.0 as usize)
    }
}

impl Config {
    pub fn new(key: StaticPrivateKey) -> Self {
        Config::from_oracle(key)
    }
}

impl<O: DhOracle> Config<O> {
    pub fn from_oracle(oracle: O) -> Self {
        Config {
            static_: StaticInitiatorConfig::from_oracle(oracle),
            // TODO(conrad): seed this
            pubkey_hasher: FixedState::with_seed(0),
            peers_by_pubkey: HashTable::default(),
            peers: PeerList(Vec::new()),
        }
    }
}

impl<O> Config<O> {
    /// Adds a new peer to this wireguard config.
    pub fn insert_peer(&mut self, peer: StaticPeerConfig) -> PeerId {
        use hashbrown::hash_table::Entry;
        match self.peers_by_pubkey.entry(
            self.pubkey_hasher.hash_one(peer.key.0),
            |&i| self.peers[i].key.0 == peer.key.0,
            |&i| self.pubkey_hasher.hash_one(self.peers[i].key.0),
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
            .find(self.pubkey_hasher.hash_one(pk.0), |&i| {
                peers[i].key.0 == pk.0
            })
            .copied()
    }
}

pub struct PeerState {
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
    keepalive_pending: bool,
}

impl Session {
    fn should_reinit(&self, now: Tai64N, _hs: &SessionHandshake) -> bool {
        (self.sent + REKEY_TIMEOUT < now) && (now < self.started + REKEY_ATTEMPT_TIME)
    }

    fn should_rekey(&self, now: Tai64N, ts: &SessionTransport) -> bool {
        (self.started + REKEY_AFTER_TIME < now) || (ts.encrypt.counter() >= REKEY_AFTER_MESSAGES)
    }
    fn should_keepalive(&self, now: Tai64N, _ts: &SessionTransport) -> bool {
        self.sent + KEEPALIVE_TIMEOUT < now
    }
    fn should_reject(&self, now: Tai64N, ts: &SessionTransport) -> bool {
        self.should_expire(now) || (ts.encrypt.counter() >= REJECT_AFTER_MESSAGES)
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
    #[zeroize(skip)]
    Transport(SessionTransport),
}

#[derive(Zeroize)]
struct SessionHandshake {
    #[zeroize(skip)]
    esk_i: EphemeralPrivateKey,
    state: HandshakeState,
}

struct SessionTransport {
    /// who will the outgoing messages be received by
    receiver: u32,
    encrypt: EncryptionKey,
    decrypt: DecryptionKey,
}

impl PeerState {
    pub fn new(endpoint: Option<SocketAddr>) -> Self {
        Self {
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
        let n = ts.encrypt.counter();
        let tag = ts.encrypt.encrypt::<CryptoCore>(payload);

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

/// Handle to a freshly-completed handshake's data session, returned to the
/// caller of `recv_message`. Use [`MessageEncrypter::encrypt`] to send the
/// first transport packet.
pub struct MessageEncrypter(u32);

impl MessageEncrypter {
    /// Returns `None` if the session has been removed/rotated or has already
    /// crossed REJECT_AFTER_{MESSAGES,TIME} since the encrypter was issued.
    pub fn encrypt(self, sessions: &Sessions, payload: &mut [u8]) -> Option<EncryptedMetadata> {
        let mut state_ref = sessions.dynamic.borrow_mut();
        let state = &mut *state_ref;

        let now = state.now;
        let session = state.peers_by_session.get_mut(&self.0)?;
        let SessionState::Transport(ts) = &session.state else {
            return None;
        };
        if session.should_reject(now, ts) {
            return None;
        }
        let peer = &mut state.peers[session.peer];

        Some(peer.force_encrypt(session, payload, now))
    }

    /// Encrypts the payload and attaches the wireguard framing in-place.
    ///
    /// The payload is defined to be `buffer[16..buffer.len()-16]`, as first and last
    /// 16 bytes are reserved for the wireguard framing.
    ///
    /// Returns `false` (with `buffer` left in an unspecified state) if the
    /// session has expired between issuance and use.
    pub fn encrypt_and_frame(self, sessions: &Sessions, buffer: &mut [u8]) -> bool {
        let len = buffer.len();
        let payload = &mut buffer[16..len - 16];
        let Some(meta) = self.encrypt(sessions, payload) else {
            return false;
        };
        meta.frame_in_place(buffer);
        true
    }
}

type Tai64NBytes = [u8; 12];

// session IDs are chosen randomly by us, thus, are not vulnerable to hashdos
// and don't need a high-quality hasher
type SessionMap = HashMap<u32, Box<Session>, FixedState>;

pub struct Sessions<O = StaticPrivateKey> {
    config: Config<O>,
    dynamic: RefCell<DynamicState>,
}

pub struct DynamicState {
    rng: StdRng,
    cookie: CookieState,

    last_reseed: Tai64N,
    now: Tai64N,

    last_rate_reset: Tai64N,
    ip_rate_limit: CountMinSketch,

    peers: PeerList<PeerState>,
    peers_by_session: SessionMap,

    timers: BinaryHeap<TimerEntry>,
}

impl DynamicState {
    fn new(peers: &PeerList<StaticPeerConfig>, rng: &mut impl CryptoRng) -> Self {
        Self {
            cookie: CookieState::new(rng),
            last_reseed: Tai64N(Tai64(0), 0),
            now: Tai64N(Tai64(0), 0),
            last_rate_reset: Tai64N(Tai64(0), 0),
            ip_rate_limit: CountMinSketch::with_params(10.0 / 20_000.0, 0.01, rng),
            rng: StdRng::from_rng(rng),
            peers: PeerList(peers.0.iter().map(|p| PeerState::new(p.endpoint)).collect()),
            peers_by_session: HashMap::default(),
            timers: BinaryHeap::new(),
        }
    }
}

impl Sessions {
    pub fn new(config: Config, rng: &mut impl CryptoRng) -> Self {
        Self::new_with(config, rng)
    }
}

impl<O> Sessions<O> {
    pub fn new_with(config: Config<O>, rng: &mut impl CryptoRng) -> Self {
        Self {
            dynamic: RefCell::new(DynamicState::new(&config.peers, rng)),
            config,
        }
    }
}

impl<O: DhOracle> Sessions<O> {
    /// Should be called at least once per second.
    /// Should be called until it returns None.
    pub fn turn(&self, now: Tai64N, rng: &mut impl CryptoRng) -> Option<MaintenanceMsg> {
        let mut state = self.dynamic.borrow_mut();
        if now > state.now {
            state.now = now;
            if now.duration_since(&state.last_reseed).unwrap() > Duration::from_secs(120) {
                state.cookie.generate(rng);

                state.rng = StdRng::from_rng(&mut *rng);
                state.last_reseed = state.now;
            }
            if now.duration_since(&state.last_rate_reset).unwrap() > Duration::from_secs(1) {
                state.ip_rate_limit.reset(rng);
            }
        }
        drop(state);

        time::tick_timers(self)
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidMessage,
    DecryptionError,
    KeyExchangeError,
    Unaligned,
    Rejected,
}

impl From<CryptoError> for Error {
    fn from(value: CryptoError) -> Self {
        match value {
            CryptoError::KeyExchangeError => Error::KeyExchangeError,
            CryptoError::DecryptionError => Error::DecryptionError,
            CryptoError::Rejected => Error::Rejected,
        }
    }
}

pub enum Message<'a> {
    // This should be sent back to the client
    Write(&'a mut [u8]),
    // This can be processed appropriately
    Read(PeerId, &'a mut [u8]),
    Noop,
    HandshakeComplete(MessageEncrypter),
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

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
struct Keepalive {
    header: DataHeader,
    tag: rustyguard_types::Tag,
}

fn write_msg<'b, T: IntoBytes + Immutable>(buf: &'b mut [u8], t: &T) -> &'b mut [u8] {
    let resp_msg = &mut buf[..core::mem::size_of::<T>()];
    resp_msg.copy_from_slice(t.as_bytes());
    resp_msg
}

impl DynamicState {
    fn overloaded(&mut self, ip: IpAddr) -> bool {
        let key = match ip {
            IpAddr::V4(v4) => v4.to_bits() as u64,
            IpAddr::V6(v6) => (v6.to_bits() >> 64) as u64,
        };
        self.ip_rate_limit.count(&key) > 10
    }
}

impl<O> Sessions<O> {
    fn write_cookie_message<'b>(
        &self,
        mac1: Mac,
        receiver: u32,
        cookie: Cookie,
        buf: &'b mut [u8],
    ) -> &'b mut [u8] {
        // Generating a random nonce and encrypting the cookie takes 900ns
        // on my M2 Max. Total time to verify the handshake msg is 2us.
        // This brings us to 500k handshakes processed per second.
        // As I said above, this should be parallisable with an rng per thread.
        let mut nonce = [0u8; 24];
        self.dynamic.borrow_mut().rng.fill_bytes(&mut nonce);
        let cookie = encrypt_cookie(cookie, &self.config.static_.cookie_key, &nonce, &mac1);

        let msg = CookieMessage {
            _type: little_endian::U32::new(MSG_COOKIE),
            receiver: little_endian::U32::new(receiver),
            nonce,
            cookie,
        };
        write_msg(buf, &msg)
    }

    #[inline(never)]
    fn decrypt_packet<'m>(
        &self,
        socket: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<(PeerId, &'m mut [u8]), Error> {
        let mut state_ref = self.dynamic.borrow_mut();
        let state = &mut *state_ref;

        unsafe_log!("[{socket:?}] parsed as data packet");

        let (header, payload_and_tag) =
            DataHeader::message_mut_from(msg).ok_or(Error::InvalidMessage)?;

        let session_id = header.receiver.get();
        let Some(session) = state.peers_by_session.get_mut(&session_id) else {
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

        // WireGuard whitepaper §6.5: only update peer.endpoint after AEAD auth.
        let payload = ts
            .decrypt
            .decrypt::<CryptoCore>(header.counter.get(), payload_and_tag)?;

        let peer_idx = session.peer;
        let needs_keepalive =
            session.sent + KEEPALIVE_TIMEOUT < state.now && !session.keepalive_pending;
        if needs_keepalive {
            session.keepalive_pending = true;
        }
        let peer = &mut state.peers[peer_idx];
        peer.endpoint = Some(socket);

        if needs_keepalive {
            state.timers.push(TimerEntry {
                time: state.now,
                kind: TimerEntryType::Keepalive { session_id },
            });
        }

        Ok((peer_idx, payload))
    }
}

impl<O: DhOracle> Sessions<O> {
    pub fn send_message(
        &mut self,
        peer_idx: PeerId,
        payload: &mut [u8],
    ) -> Result<SendMessage, Error> {
        let mut state_ref = self.dynamic.borrow_mut();
        let state = &mut *state_ref;

        let peer = state.peers.get_mut(peer_idx).ok_or(Error::Rejected)?;
        let Some(ep) = peer.endpoint else {
            return Err(Error::Rejected);
        };

        match peer.encrypt_message(&mut state.peers_by_session, payload, state.now) {
            // we encrypted the message in-place in payload.
            Some(metadata) => {
                let session_id = peer.current_transport.unwrap();
                let session = state.peers_by_session.get_mut(&session_id).unwrap();
                let SessionState::Transport(ts) = &session.state else {
                    unreachable!()
                };

                if ts.encrypt.counter() >= REKEY_AFTER_MESSAGES {
                    // the encryption key needs rotating. schedule a rekey attempt
                    state.timers.push(TimerEntry {
                        time: state.now,
                        kind: TimerEntryType::RekeyAttempt { session_id },
                    });
                }
                Ok(SendMessage::Data(ep, metadata))
            }
            // we could not encrypt the message as we don't yet have an active session.
            // create a handshake init message to be sent.
            None => {
                drop(state_ref);
                Ok(SendMessage::Maintenance(MaintenanceMsg {
                    socket: ep,
                    data: MaintenanceRepr::Init(new_handshake(self, peer_idx)?),
                }))
            }
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
    /// * [`Message::HandshakeComplete`] - We just completed a handshake as the
    ///   initiator; the returned [`MessageEncrypter`] can be used to send the
    ///   first transport packet on this fresh session.
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
        let (msg_type, _) =
            little_endian::U32::ref_from_prefix(msg).map_err(|_| Error::InvalidMessage)?;
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
}

#[cfg(test)]
mod tests {
    use core::net::SocketAddr;

    use crate::{PublicKey, StaticPrivateKey};
    use alloc::boxed::Box;
    use rand::{
        rngs::{OsRng, StdRng},
        Rng, RngCore, SeedableRng, TryRngCore,
    };
    use rustyguard_crypto::{DhOracle, Key, StaticPeerConfig};
    use tai64::Tai64N;
    use zerocopy::IntoBytes;

    use crate::{Config, PeerId, Sessions};

    fn gen_sk(r: &mut impl Rng) -> StaticPrivateKey {
        let mut b = [0u8; 32];
        r.fill_bytes(&mut b);
        StaticPrivateKey(b)
    }

    fn session_with_peer(
        secret_key: StaticPrivateKey,
        peer_public_key: PublicKey,
        preshared_key: Key,
        endpoint: SocketAddr,
    ) -> (PeerId, Sessions) {
        let peer = StaticPeerConfig::new(peer_public_key, Some(preshared_key), Some(endpoint));
        let mut config = Config::new(secret_key);
        let id = config.insert_peer(peer);
        let session = Sessions::new(config, &mut OsRng.unwrap_err());
        (id, session)
    }

    #[repr(align(16))]
    struct AlignedPacket([u8; 256]);

    #[test]
    fn handshake_happy() {
        let server_addr: SocketAddr = "10.0.1.1:1234".parse().unwrap();
        let client_addr: SocketAddr = "10.0.2.1:1234".parse().unwrap();
        let ssk_i = gen_sk(&mut OsRng.unwrap_err());
        let ssk_r = gen_sk(&mut OsRng.unwrap_err());
        let spk_i = ssk_i.x25519_pubkey();
        let spk_r = ssk_r.x25519_pubkey();
        let mut psk = Key::default();
        OsRng.unwrap_err().fill_bytes(&mut psk);

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
                crate::Message::HandshakeComplete(encryptor) => encryptor,
                _ => panic!("expecting noop"),
            }
        };

        // wrap the messasge and encode into buffer
        let data_msg = {
            let metadata = encryptor.encrypt(&sessions_i, &mut msg).unwrap();
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

    /// Regression for whitepaper §6.5: a forged data packet from a wrong
    /// source address must not redirect the peer's outbound endpoint.
    #[test]
    fn forged_packet_does_not_update_peer_endpoint() {
        let server_addr: SocketAddr = "10.0.1.1:1234".parse().unwrap();
        let client_addr: SocketAddr = "10.0.2.1:1234".parse().unwrap();
        let attacker_addr: SocketAddr = "10.0.3.1:9999".parse().unwrap();

        let ssk_i = gen_sk(&mut OsRng.unwrap_err());
        let ssk_r = gen_sk(&mut OsRng.unwrap_err());
        let spk_i = ssk_i.x25519_pubkey();
        let spk_r = ssk_r.x25519_pubkey();
        let mut psk = Key::default();
        OsRng.unwrap_err().fill_bytes(&mut psk);

        let (peer_r, mut sessions_i) = session_with_peer(ssk_i, spk_r, psk, server_addr);
        let (peer_i, mut sessions_r) = session_with_peer(ssk_r, spk_i, psk, client_addr);

        let mut buf = Box::new(AlignedPacket([0; 256]));
        let mut msg = *b"Hello, World!\0\0\0";

        let m = match sessions_i.send_message(peer_r, &mut msg).unwrap() {
            crate::SendMessage::Maintenance(m) => m,
            _ => panic!("expecting handshake"),
        };
        let response_buf = {
            let handshake_buf = &mut buf.0[..m.data().len()];
            handshake_buf.copy_from_slice(m.data());
            match sessions_r.recv_message(client_addr, handshake_buf).unwrap() {
                crate::Message::Write(buf) => buf,
                _ => panic!("expecting write"),
            }
        };
        let encryptor = match sessions_i.recv_message(server_addr, response_buf).unwrap() {
            crate::Message::HandshakeComplete(e) => e,
            _ => panic!("expecting handshake complete"),
        };
        let data_msg = {
            let metadata = encryptor.encrypt(&sessions_i, &mut msg).unwrap();
            buf.0[..16].copy_from_slice(metadata.header.as_bytes());
            buf.0[16..32].copy_from_slice(&msg);
            buf.0[32..48].copy_from_slice(&metadata.tag.0);
            &mut buf.0[..48]
        };
        match sessions_r.recv_message(client_addr, data_msg).unwrap() {
            crate::Message::Read(_, _) => {}
            _ => panic!("expecting read"),
        }

        let mut forged = Box::new(AlignedPacket([0; 256]));
        forged.0[..48].copy_from_slice(&buf.0[..48]);
        forged.0[47] ^= 0x01;
        let _ = sessions_r.recv_message(attacker_addr, &mut forged.0[..48]);

        let mut reply = *b"hi back\0\0\0\0\0\0\0\0\0";
        match sessions_r.send_message(peer_i, &mut reply).unwrap() {
            crate::SendMessage::Data(addr, _) => assert_eq!(addr, client_addr),
            crate::SendMessage::Maintenance(m) => assert_eq!(m.to(), client_addr),
        }
    }

    #[test]
    fn snapshot() {
        let mut rng = StdRng::seed_from_u64(1);
        let server_addr: SocketAddr = "10.0.1.1:1234".parse().unwrap();
        let client_addr: SocketAddr = "10.0.2.1:1234".parse().unwrap();
        let ssk_i = gen_sk(&mut rng);
        let ssk_r = gen_sk(&mut rng);
        let spk_i = ssk_i.x25519_pubkey();
        let spk_r = ssk_r.x25519_pubkey();
        let mut psk = Key::default();
        rng.fill_bytes(&mut psk);

        let now = Tai64N::UNIX_EPOCH;

        let peer = StaticPeerConfig::new(spk_r, Some(psk), Some(server_addr));
        let mut config = Config::new(ssk_i);
        let peer_r = config.insert_peer(peer);
        let mut sessions_i = Sessions::new(config, &mut rng);
        sessions_i.turn(now, &mut rng);

        let peer = StaticPeerConfig::new(spk_i, Some(psk), Some(client_addr));
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
                crate::Message::HandshakeComplete(encryptor) => encryptor,
                _ => panic!("expecting noop"),
            }
        };

        // wrap the messasge and encode into buffer
        let data_msg = {
            let metadata = encryptor.encrypt(&sessions_i, &mut msg).unwrap();
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
