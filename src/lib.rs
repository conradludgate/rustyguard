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

use bytemuck::{Pod, Zeroable};
use crypto::{
    mac, mac1_key, mac2_key, Cookie, DecryptionKey, EncryptionKey, HandshakeState, Key, Mac, Tag,
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
    started: Tai64N,
    sent: Tai64N,
    esk_i: StaticSecret,
    state: HandshakeState,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct PeerCipherState {
    started: Tai64N,
    sent: Tai64N,
    /// who will the outgoing messages be received by
    receiver: u32,
    encrypt: EncryptionKey,
    decrypt: DecryptionKey,
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
                started: Tai64N(Tai64(0), 0),
                sent: Tai64N(Tai64(0), 0),
                esk_i: StaticSecret::from([0; 32]),
                state: HandshakeState::default(),
            },
            ciphers: PeerCipherState {
                started: Tai64N(Tai64(0), 0),
                sent: Tai64N(Tai64(0), 0),
                receiver: Default::default(),
                encrypt: Default::default(),
                decrypt: Default::default(),
            },
            last_sent_mac1: [0; 16],
        }
    }

    fn encrypt_message(&mut self, payload: &mut [u8], now: Tai64N) -> Option<(DataHeader, Tag)> {
        let session = &mut self.ciphers;
        if session.sent.0 .0 == 0 {
            return None;
        }
        if session.sent + REJECT_AFTER_TIME < now {
            return None;
        }
        if session.encrypt.counter >= REJECT_AFTER_MESSAGES {
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
    InitAttempt { peer_idx: usize },
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
                    if peer.handshake.sent + REKEY_TIMEOUT < self.now
                        && self.now < peer.handshake.started + REKEY_ATTEMPT_TIME
                        && (peer.ciphers.started + REKEY_AFTER_TIME < self.now
                            || peer.ciphers.encrypt.counter >= REKEY_AFTER_MESSAGES)
                    {
                        return Some(MaintenanceMsg {
                            socket: peer.endpoint.expect("a rekey event should not be scheduled if we've never seen this endpoint before"),
                            data: MaintenanceRepr::Init(HandshakeInit::new(self, peer_idx)),
                        });
                    }
                }
                TimerEntryType::RekeyAttempt { peer_idx } => {
                    let peer = &mut self.config.peers[peer_idx];
                    if peer.handshake.sent + REKEY_AFTER_TIME < self.now {
                        return Some(MaintenanceMsg {
                            socket: peer.endpoint.expect("a rekey event should not be scheduled if we've never seen this endpoint before"),
                            data: MaintenanceRepr::Init(HandshakeInit::new(self, peer_idx)),
                        });
                    }
                }
                TimerEntryType::Keepalive { peer_idx } => {
                    let peer = &mut self.config.peers[peer_idx];
                    if peer.ciphers.sent + KEEPALIVE_TIMEOUT < self.now {
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
        let peer = self.config.peers.get_mut(peer_idx).ok_or(Error::Rejected)?;
        let Some(ep) = peer.endpoint else {
            return Err(Error::Rejected);
        };
        match peer.encrypt_message(payload, self.now) {
            Some((header, tag)) => {
                if peer.ciphers.encrypt.counter >= REKEY_AFTER_MESSAGES {
                    self.timers.push(TimerEntry {
                        time: self.now,
                        kind: TimerEntryType::RekeyAttempt { peer_idx },
                    });
                }
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
            // cookie message is always smaller than the initial message
            ControlFlow::Break(cookie) => return Ok(write_msg(msg, &cookie)),
            ControlFlow::Continue(msg) => msg,
        };

        let mut hs = HandshakeState::default();

        let data = init_msg.decrypt(&mut hs, &self.config)?;

        // check if we know this peer
        let peer_idx = self
            .config
            .get_peer_idx(&data.spk_i)
            .ok_or(Error::Rejected)?;
        let peer = &mut self.config.peers[peer_idx];

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
        peer.ciphers = PeerCipherState {
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
        let resp_msg = match HandshakeResp::verify(msg, self, socket)? {
            // cookie message is always smaller than the initial message
            ControlFlow::Break(cookie) => return Ok(Message::Write(write_msg(msg, &cookie))),
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

        resp_msg.decrypt(peer, &self.config.private_key)?;
        peer.endpoint = Some(socket);

        let (initiator, responder) = peer.handshake.state.split();
        peer.handshake.zeroize();

        session.insert(SessionType::Cipher(peer_idx));
        peer.ciphers = PeerCipherState {
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
        let cookie_msg = bytemuck::try_from_bytes_mut::<CookieMessage>(msg)
            .map_err(|_| Error::InvalidMessage)?;

        let (SessionType::Cipher(peer_idx) | SessionType::Handshake(peer_idx)) = self
            .peers_by_session
            .get(&cookie_msg.receiver.get())
            .ok_or(Error::Rejected)?;
        let peer = &mut self.config.peers[*peer_idx];

        let cookie = *cookie_msg.cookie.decrypt_cookie(
            &peer.mac2_key,
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
    ) -> Result<(usize, &'m mut [u8]), Error> {
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

        session
            .decrypt
            .decrypt(header.counter.get(), payload, Tag::from_slice(tag))?;

        Ok((peer_idx, payload))
    }
}

impl HandshakeInit {
    #[allow(dead_code)]
    fn new(state: &mut Sessions, peer_idx: usize) -> Self {
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
    use blake2::digest::generic_array::GenericArray;
    use chacha20poly1305::Key;
    use rand::{rngs::OsRng, RngCore};
    use tai64::Tai64N;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::{Config, CookieMessage, DataHeader, HandshakeInit, HandshakeResp, Peer, Sessions};

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

        assert_eq!(core::mem::size_of::<Peer>(), 448);
    }

    fn session_with_peer(
        secret_key: StaticSecret,
        peer_public_key: PublicKey,
        preshared_key: Key,
        endpoint: SocketAddr,
    ) -> Sessions {
        let peer = Peer::new(peer_public_key, Some(preshared_key), Some(endpoint));
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

        let mut sessions_i = session_with_peer(ssk_i, spk_r, psk, server_addr);
        let mut sessions_r = session_with_peer(ssk_r, spk_i, psk, client_addr);

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
