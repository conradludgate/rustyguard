//! wireguard timers

use rustyguard_crypto::CryptoPrimatives;
use tai64::Tai64N;

use crate::{
    EncryptedMetadata, Error, Event, Keepalive, MaintenanceMsg, MaintenanceRepr, SessionState,
    Sessions, REKEY_TIMEOUT,
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
    ExpireHandshake { session_id: u32 },
}

pub(crate) fn tick_timers<C: CryptoPrimatives>(sessions: &Sessions<C>) -> Option<Event<C>> {
    let mut state_ref = sessions.dynamic.borrow_mut();
    let mut state = &mut *state_ref;

    while state.timers.peek().is_some_and(|t| t.time < state.now) {
        let entry = state.timers.pop().unwrap().kind;
        match entry {
            TimerEntryType::InitAttempt { session_id }
            | TimerEntryType::RekeyAttempt { session_id } => {
                let Some(session) = state.peers_by_session.get_mut(&session_id) else {
                    continue;
                };
                let peer_idx = session.peer;

                // only re-init if
                // 1. it's been REKEY_TIMEOUT seconds since our last attempt
                // 2. it's not been more than REKEY_ATTEMPT_TIME seconds since we started
                // 3. the session needs to be re-init
                let should_reinit = match &session.state {
                    SessionState::Handshake(hs) => session.should_reinit(state.now, hs),
                    SessionState::Transport(ts) => {
                        session.should_rekey(state.now, ts)
                            && state.peers[peer_idx].current_handshake.is_none()
                    }
                };

                if should_reinit {
                    // Must drop the borrow before starting a handshake,
                    // which needs its own mutable borrow of dynamic.
                    drop(state_ref);
                    let result = sessions.start_handshake(peer_idx);
                    // Re-borrow for the next loop iteration.
                    state_ref = sessions.dynamic.borrow_mut();
                    state = &mut *state_ref;
                    match result {
                        Ok(work) => return Some(Event::Handshake(work)),
                        // Temporary saturation must not discard the only rekey
                        // timer for an established transport.
                        Err(Error::HandshakeLimit) => state.timers.push(TimerEntry {
                            time: state.now + REKEY_TIMEOUT,
                            kind: TimerEntryType::InitAttempt { session_id },
                        }),
                        Err(_) => {}
                    }
                }
            }
            TimerEntryType::ExpireTransport { session_id } => {
                let Some(session) = state.peers_by_session.get_mut(&session_id) else {
                    continue;
                };

                let peer_idx = session.peer;
                let peer = &mut state.peers[peer_idx];

                if session.should_expire(state.now) {
                    if peer.current_transport == Some(session_id) {
                        peer.current_transport = None;
                    }
                    state.peers_by_session.remove(&session_id);
                }
            }
            TimerEntryType::ExpireHandshake { session_id } => {
                // Completed handshakes are reaped by ExpireTransport instead.
                let Some(session) = state.peers_by_session.get(&session_id) else {
                    continue;
                };
                if !matches!(session.state, SessionState::Handshake(_)) {
                    continue;
                }
                let peer_idx = session.peer;
                let peer = &mut state.peers[peer_idx];
                if peer.current_handshake == Some(session_id) {
                    peer.current_handshake = None;
                }
                state.peers_by_session.remove(&session_id);
            }
            TimerEntryType::Keepalive { session_id } => {
                let Some(session) = state.peers_by_session.get_mut(&session_id) else {
                    continue;
                };
                session.keepalive_pending = false;
                let peer = &mut state.peers[session.peer];

                let should_keepalive = match &session.state {
                    SessionState::Handshake(_) => false,
                    SessionState::Transport(ts) => session.should_keepalive(state.now, ts),
                };

                if should_keepalive {
                    let Some(EncryptedMetadata {
                        header,
                        tag,
                        payload_len: _,
                    }) = peer.encrypt_message::<C>(&mut state.peers_by_session, &mut [], state.now)
                    else {
                        continue;
                    };
                    let socket = peer.endpoint.expect("a keepalive event should not be scheduled if we've never seen this endpoint before");

                    return Some(Event::Write(MaintenanceMsg {
                        socket,
                        data: MaintenanceRepr::Data(Keepalive { header, tag }),
                    }));
                }
            }
        }
    }

    None
}
