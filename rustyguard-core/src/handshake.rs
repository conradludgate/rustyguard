use crate::time::{TimerEntry, TimerEntryType};
use crate::{
    DynamicState, Error, Event, MaintenanceMsg, MaintenanceRepr, Message, MessageEncrypter, PeerId,
    Session, SessionHandshake, SessionState, SessionTransport, Sessions, Tai64N, REJECT_AFTER_TIME,
    REKEY_AFTER_TIME, REKEY_ATTEMPT_TIME, REKEY_TIMEOUT,
};
use alloc::{boxed::Box, sync::Arc};
use core::{net::SocketAddr, ops::ControlFlow};
use rand_core::RngCore;
use rustyguard_crypto::{
    decrypt_cookie_with, CryptoPrimatives, DecryptHandshakeInit, DecryptHandshakeResp,
    DecryptHandshakeTimestamp, EncryptHandshakeInit, EphemeralPrivateKey, HandshakeState, HasMac,
    SharedSecret,
};
use rustyguard_types::{CookieMessage, HandshakeInit, HandshakeResp};
use zerocopy::FromBytes;
use zeroize::Zeroize;

pub(crate) struct PendingJob {
    expires: Tai64N,
}

/// One owned static-key DH operation, with no borrow of the engine or packet.
///
/// Use the configuration's local static key with [`Self::peer_key`], then call
/// [`Self::complete`]. The result may request a second agreement. Device errors
/// and runtime choices stay with the caller; drop this value to cancel. Never
/// reuse an agreement result for a different request.
///
/// Pending jobs expire after the handshake attempt window (90 seconds, measured
/// by [`Sessions::turn`]). Late results, results for another engine and responses
/// to replaced handshakes are rejected. Call `turn` while work is pending.
/// Dropping the engine or request does not cancel physical work on an HSM.
#[must_use]
pub struct Handshake<C = rustyguard_crypto::CryptoCore> {
    socket: SocketAddr,
    job: Arc<PendingJob>,
    kind: HandshakeKind<C>,
}

enum HandshakeKind<C> {
    Init {
        request: EncryptHandshakeInit<C>,
        session_id: u32,
        generation: u64,
    },
    Identity(DecryptHandshakeInit<C>),
    Timestamp(DecryptHandshakeTimestamp<C>),
    Response {
        request: DecryptHandshakeResp<C>,
        session_id: u32,
        generation: u64,
        sender: u32,
    },
}

impl<C: CryptoPrimatives> Handshake<C> {
    /// The remote public key for this agreement. On incoming work this may be
    /// an unauthenticated claimed identity; do not use it as proof of identity.
    pub fn peer_key(&self) -> crate::PublicKey {
        match &self.kind {
            HandshakeKind::Init { request, .. } => request.peer_key(),
            HandshakeKind::Identity(request) => request.peer_key(),
            HandshakeKind::Timestamp(request) => request.peer_key(),
            HandshakeKind::Response { request, .. } => request.peer_key(),
        }
    }

    /// Last protocol time at which this work may complete is strictly before
    /// this deadline. The caller can use it to bound device waits.
    pub fn deadline(&self) -> Tai64N {
        self.job.expires
    }

    /// Resume this operation on the engine that issued it. No caller-provided
    /// secret or transcript is installed unless this job is still live.
    pub fn complete(self, sessions: &Sessions<C>, secret: SharedSecret) -> Result<Event<C>, Error> {
        let mut state_ref = sessions.dynamic.borrow_mut();
        let state = &mut *state_ref;
        if state.now >= self.job.expires {
            return Err(Error::Rejected);
        }
        let weak = Arc::downgrade(&self.job);
        if !state
            .pending_handshakes
            .iter()
            .any(|registered| registered.ptr_eq(&weak))
        {
            return Err(Error::Rejected);
        }
        match self.kind {
            HandshakeKind::Identity(request) => {
                let request = request.complete(secret)?;
                // This is still only a claimed identity. Reject unknown peers
                // before another device operation; commit nothing yet.
                sessions
                    .config
                    .get_peer_idx(&request.peer_key())
                    .ok_or(Error::Rejected)?;
                Ok(Event::Handshake(Self {
                    kind: HandshakeKind::Timestamp(request),
                    ..self
                }))
            }
            HandshakeKind::Timestamp(request) => {
                let data = request.complete(secret)?;
                let peer_idx = sessions
                    .config
                    .get_peer_idx(&data.static_key())
                    .ok_or(Error::Rejected)?;
                let peer_config = &sessions.config.peers[peer_idx];
                let peer = &mut state.peers[peer_idx];
                if *data.timestamp() <= peer.latest_ts {
                    return Err(Error::Rejected);
                }
                let timestamp = *data.timestamp();
                let mut session_id = state.rng.next_u32();
                while state.peers_by_session.contains_key(&session_id) {
                    session_id = state.rng.next_u32();
                }
                let esk_r = EphemeralPrivateKey::generate(&mut state.rng);
                let (response, mut hs) =
                    data.respond(&esk_r, peer_config, session_id, peer.cookie.as_ref())?;
                let (encrypt, decrypt) = hs.split::<C>(false);
                peer.latest_ts = timestamp;
                peer.last_sent_mac1 = response.mac1;
                peer.current_transport = Some(session_id);
                state.peers_by_session.insert(
                    session_id,
                    Box::new(Session {
                        peer: peer_idx,
                        started: state.now,
                        sent: state.now,
                        state: SessionState::Transport(SessionTransport {
                            receiver: response.receiver.get(),
                            encrypt,
                            decrypt,
                        }),
                        keepalive_pending: false,
                    }),
                );
                state.timers.push(TimerEntry {
                    time: state.now + REJECT_AFTER_TIME,
                    kind: TimerEntryType::ExpireTransport { session_id },
                });
                Ok(Event::Write(MaintenanceMsg {
                    socket: self.socket,
                    data: MaintenanceRepr::Resp(response),
                }))
            }
            HandshakeKind::Init {
                request,
                session_id,
                generation,
            } => {
                let session = state
                    .peers_by_session
                    .get_mut(&session_id)
                    .ok_or(Error::Rejected)?;
                let SessionState::Handshake(hs) = &mut session.state else {
                    return Err(Error::Rejected);
                };
                if hs.generation != generation
                    || hs.state.is_some()
                    || state.peers[session.peer].current_handshake != Some(session_id)
                {
                    return Err(Error::Rejected);
                }
                let (message, transcript) = request.complete(secret);
                hs.state = Some(transcript);
                session.sent = state.now;
                state.peers[session.peer].last_sent_mac1 = message.mac1;
                state.timers.push(TimerEntry {
                    time: state.now + REKEY_TIMEOUT,
                    kind: TimerEntryType::InitAttempt { session_id },
                });
                Ok(Event::Write(MaintenanceMsg {
                    socket: self.socket,
                    data: MaintenanceRepr::Init(message),
                }))
            }
            HandshakeKind::Response {
                request,
                session_id,
                generation,
                sender,
            } => {
                let session = state
                    .peers_by_session
                    .get_mut(&session_id)
                    .ok_or(Error::Rejected)?;
                let SessionState::Handshake(hs) = &mut session.state else {
                    return Err(Error::Rejected);
                };
                let peer = &mut state.peers[session.peer];
                if hs.generation != generation
                    || hs.state.is_none()
                    || peer.current_handshake != Some(session_id)
                {
                    return Err(Error::Rejected);
                }
                let mut completed = request.complete(secret)?;
                let (encrypt, decrypt) = completed.split::<C>(true);
                peer.current_handshake = None;
                peer.current_transport = Some(session_id);
                peer.endpoint = Some(self.socket);
                hs.zeroize();
                session.state = SessionState::Transport(SessionTransport {
                    receiver: sender,
                    encrypt,
                    decrypt,
                });
                session.started = state.now;
                session.sent = state.now;
                state.timers.push(TimerEntry {
                    time: state.now + REKEY_AFTER_TIME,
                    kind: TimerEntryType::RekeyAttempt { session_id },
                });
                state.timers.push(TimerEntry {
                    time: state.now + REJECT_AFTER_TIME,
                    kind: TimerEntryType::ExpireTransport { session_id },
                });
                Ok(Event::HandshakeComplete(MessageEncrypter(session_id)))
            }
        }
    }
}

impl DynamicState {
    fn reserve_handshake(
        &mut self,
        limit: usize,
        expires: Tai64N,
    ) -> Result<Arc<PendingJob>, Error> {
        self.pending_handshakes
            .retain(|job| job.upgrade().is_some_and(|job| self.now < job.expires));
        if self.pending_handshakes.len() >= limit {
            return Err(Error::HandshakeLimit);
        }
        let job = Arc::new(PendingJob { expires });
        self.pending_handshakes.push(Arc::downgrade(&job));
        Ok(job)
    }
}

impl<C: CryptoPrimatives> Sessions<C> {
    #[inline(never)]
    pub(crate) fn handle_handshake_init<'m>(
        &self,
        addr: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<Message<'m, C>, Error> {
        let mut state = self.dynamic.borrow_mut();
        let init_msg = HandshakeInit::mut_from_bytes(msg).map_err(|_| Error::InvalidMessage)?;
        let overload = state.overloaded(addr.ip());
        match init_msg.verify_with::<C>(&self.config.mac1_key, overload, &state.cookie, addr)? {
            ControlFlow::Break(cookie) => {
                drop(state);
                return Ok(Message::Write(self.write_cookie_message(
                    init_msg.mac1,
                    init_msg.sender.get(),
                    cookie,
                    msg,
                )));
            }
            ControlFlow::Continue(_) => {}
        }
        let expires = state.now + REKEY_ATTEMPT_TIME;
        let job = state.reserve_handshake(self.config.max_pending_handshakes, expires)?;
        let work = Handshake {
            socket: addr,
            job,
            kind: HandshakeKind::Identity(DecryptHandshakeInit::<C>::new(
                *init_msg,
                HandshakeState::default(),
                &self.config.public_key,
            )),
        };
        drop(state);
        Ok(Message::Handshake(Box::new(work)))
    }

    #[inline(never)]
    pub(crate) fn handle_handshake_resp<'m>(
        &self,
        addr: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<Message<'m, C>, Error> {
        let mut state = self.dynamic.borrow_mut();
        let resp = HandshakeResp::mut_from_bytes(msg).map_err(|_| Error::InvalidMessage)?;
        let overload = state.overloaded(addr.ip());
        match resp.verify_with::<C>(&self.config.mac1_key, overload, &state.cookie, addr)? {
            ControlFlow::Break(cookie) => {
                drop(state);
                return Ok(Message::Write(self.write_cookie_message(
                    resp.mac1,
                    resp.sender.get(),
                    cookie,
                    msg,
                )));
            }
            ControlFlow::Continue(_) => {}
        }
        let session_id = resp.receiver.get();
        let session = state
            .peers_by_session
            .get(&session_id)
            .ok_or(Error::Rejected)?;
        let SessionState::Handshake(hs) = &session.state else {
            return Err(Error::Rejected);
        };
        let transcript = hs.state.as_ref().ok_or(Error::Rejected)?;
        let expires = session.started + REKEY_ATTEMPT_TIME;
        if state.now >= expires {
            return Err(Error::Rejected);
        }
        let generation = hs.generation;
        let request = DecryptHandshakeResp::<C>::new(
            *resp,
            transcript,
            &self.config.peers[session.peer],
            &hs.esk_i,
        )?;
        let job = state.reserve_handshake(self.config.max_pending_handshakes, expires)?;
        let work = Handshake {
            socket: addr,
            job,
            kind: HandshakeKind::Response {
                request,
                session_id,
                generation,
                sender: resp.sender.get(),
            },
        };
        drop(state);
        Ok(Message::Handshake(Box::new(work)))
    }
    #[inline(never)]
    pub(crate) fn handle_cookie(&self, msg: &mut [u8]) -> Result<(), Error> {
        let mut state_ref = self.dynamic.borrow_mut();
        let state = &mut *state_ref;

        unsafe_log!("parsed as cookie packet");
        let cookie_msg = CookieMessage::mut_from_bytes(msg).map_err(|_| Error::InvalidMessage)?;

        let session = state
            .peers_by_session
            .get(&cookie_msg.receiver.get())
            .ok_or(Error::Rejected)?;
        let peer_config = &self.config.peers[session.peer];
        let peer = &mut state.peers[session.peer];

        let cookie = decrypt_cookie_with::<C>(
            &mut cookie_msg.cookie,
            &peer_config.cookie_key,
            &cookie_msg.nonce,
            &peer.last_sent_mac1,
        )?;

        peer.cookie = Some(*cookie);

        Ok(())
    }
}

impl<C: CryptoPrimatives> Sessions<C> {
    /// Begin or replace this peer's outgoing handshake without interrupting its
    /// established transport. Use this to retry after caller-managed device failure.
    /// Replacement invalidates completions for the previous outgoing handshake.
    pub fn start_handshake(&self, peer_idx: PeerId) -> Result<Handshake<C>, Error> {
        let sessions = self;
        let mut state_ref = sessions.dynamic.borrow_mut();
        let state = &mut *state_ref;
        let peer = state.peers.get_mut(peer_idx).ok_or(Error::Rejected)?;
        let peer_config = &sessions.config.peers[peer_idx];
        let socket = peer.endpoint.ok_or(Error::Rejected)?;
        let old_id = peer.current_handshake;
        let started = old_id
            .and_then(|id| state.peers_by_session.get(&id))
            .map(|session| session.started)
            .filter(|started| state.now < *started + REKEY_ATTEMPT_TIME)
            .unwrap_or(state.now);
        let expires = started + REKEY_ATTEMPT_TIME;
        if state.now >= expires {
            return Err(Error::Rejected);
        }
        let generation = state
            .handshake_generation
            .checked_add(1)
            .ok_or(Error::Rejected)?;
        let mut sender = state.rng.next_u32();
        while state.peers_by_session.contains_key(&sender) {
            sender = state.rng.next_u32();
        }
        let esk_i = EphemeralPrivateKey::generate(&mut state.rng);
        let request = EncryptHandshakeInit::<C>::new(
            HandshakeState::default(),
            &sessions.config.public_key,
            peer_config,
            &esk_i,
            state.now,
            sender,
            peer.cookie.as_ref(),
        )?;
        let job = state.reserve_handshake(sessions.config.max_pending_handshakes, expires)?;
        state.handshake_generation = generation;
        let handshake = SessionHandshake {
            esk_i,
            state: None,
            generation,
        };
        let session = match old_id.and_then(|id| state.peers_by_session.remove(&id)) {
            Some(mut session) => {
                session.sent = state.now;
                session.state = SessionState::Handshake(handshake);
                session
            }
            None => Box::new(Session {
                peer: peer_idx,
                started,
                sent: state.now,
                state: SessionState::Handshake(handshake),
                keepalive_pending: false,
            }),
        };
        state.peers[peer_idx].current_handshake = Some(sender);
        state.peers_by_session.insert(sender, session);
        state.timers.push(TimerEntry {
            time: expires,
            kind: TimerEntryType::ExpireHandshake { session_id: sender },
        });
        let work = Handshake {
            socket,
            job,
            kind: HandshakeKind::Init {
                request,
                session_id: sender,
                generation,
            },
        };
        drop(state_ref);
        Ok(work)
    }
}
