//! wireguard timers

use tai64::Tai64N;

use crate::{
    handshake::new_handshake, EncryptedMetadata, Keepalive, MaintenanceMsg, MaintenanceRepr,
    SessionState, Sessions,
};

pub(crate) struct TimerEntry {
    // min-heap by time
    pub(crate) time: Tai64N,
    pub(crate) kind: TimerEntryType,
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
pub(crate) enum TimerEntryType {
    InitAttempt { session_id: u32 },
    RekeyAttempt { session_id: u32 },
    Keepalive { session_id: u32 },
    ExpireTransport { session_id: u32 },
}

pub(crate) fn tick_timers(sessions: &Sessions) -> Option<MaintenanceMsg> {
    let mut state_ref = sessions.dynamic.borrow_mut();
    let state = &mut *state_ref;

    while state.timers.peek().is_some_and(|t| t.time < state.now) {
        let entry = state.timers.pop().unwrap().kind;
        match entry {
            TimerEntryType::InitAttempt { session_id }
            | TimerEntryType::RekeyAttempt { session_id } => {
                let session = state.peers_by_session2.get_mut(&session_id).unwrap();
                let peer_idx = session.peer;
                let peer = &sessions.config.peers[peer_idx];

                // only re-init if
                // 1. it's been REKEY_TIMEOUT seconds since our last attempt
                // 2. it's not been more than REKEY_ATTEMPT_TIME seconds since we started
                // 3. the session needs to be re-init
                let should_reinit = match &session.state {
                    SessionState::Handshake(hs) => session.should_reinit(state.now, hs),
                    SessionState::Transport(ts) => session.should_rekey(state.now, ts),
                };

                if should_reinit {
                    let socket = peer.endpoint.expect("a rekey event should not be scheduled if we've never seen this endpoint before");
                    // if this errors, it's due to a key-exchange error (diffie-hellman produced all zeros).
                    // nothign we can really do about that.
                    if let Ok(hs) = new_handshake(sessions, peer_idx) {
                        return Some(MaintenanceMsg {
                            socket,
                            data: MaintenanceRepr::Init(hs),
                        });
                    }
                }
            }
            TimerEntryType::ExpireTransport { session_id } => {
                let session = state.peers_by_session2.get_mut(&session_id).unwrap();

                let peer_idx = session.peer;
                let peer = &mut state.peers[peer_idx];

                if session.should_expire(state.now) {
                    if peer.current_transport == Some(session_id) {
                        peer.current_transport = None;
                    }
                    state.peers_by_session2.remove(&session_id);
                }
            }
            TimerEntryType::Keepalive { session_id } => {
                let session = state.peers_by_session2.get_mut(&session_id).unwrap();
                let peer = &mut state.peers[session.peer];

                let should_keepalive = match &session.state {
                    SessionState::Handshake(_) => false,
                    SessionState::Transport(ts) => session.should_keepalive(state.now, ts),
                };

                if should_keepalive {
                    let EncryptedMetadata {
                        header,
                        tag,
                        payload_len: _,
                    } = peer
                        .encrypt_message(&mut state.peers_by_session2, &mut [], state.now)
                        .expect("a keepalive should only be scheduled if the data keys are set");

                    let socket = peer.endpoint.expect("a keepalive event should not be scheduled if we've never seen this endpoint before");

                    return Some(MaintenanceMsg {
                        socket,
                        data: MaintenanceRepr::Data(Keepalive { header, tag }),
                    });
                }
            }
        }
    }

    None
}
