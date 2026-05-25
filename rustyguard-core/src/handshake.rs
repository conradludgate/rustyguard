use core::net::SocketAddr;
use core::ops::ControlFlow;

use crate::time::{TimerEntry, TimerEntryType};
use alloc::boxed::Box;
use rand_core::RngCore;
use rustyguard_crypto::{
    async_decrypt_handshake_init, async_decrypt_handshake_resp, decrypt_cookie,
    encrypt_handshake_resp, AsyncDhOracle, CryptoCore, EphemeralPrivateKey, HandshakeState, HasMac,
};
use rustyguard_types::{CookieMessage, HandshakeInit, HandshakeResp};
use zerocopy::FromBytes;
use zeroize::Zeroize;

use crate::{
    write_msg, Error, Message, MessageEncrypter, PeerId, Session, SessionHandshake, SessionState,
    SessionTransport, Sessions, REJECT_AFTER_TIME, REKEY_AFTER_TIME, REKEY_ATTEMPT_TIME,
    REKEY_TIMEOUT,
};

macro_rules! allocate_session {
    ($state:expr) => {{
        let mut session_id = $state.rng.next_u32();
        loop {
            use hashbrown::hash_map::Entry;
            match $state.peers_by_session.entry(session_id) {
                Entry::Occupied(_) => session_id = $state.rng.next_u32(),
                Entry::Vacant(v) => break v,
            }
        }
    }};
}

impl<O: AsyncDhOracle> Sessions<O> {
    #[inline(never)]
    pub(crate) async fn async_handle_handshake_init<'m>(
        &mut self,
        addr: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<&'m mut [u8], Error> {
        let state = &mut self.dynamic;

        unsafe_log!("[{addr:?}] parsed as handshake init packet");
        let init_msg = HandshakeInit::mut_from_bytes(msg).map_err(|_| Error::InvalidMessage)?;

        let overload = state.overloaded(addr.ip());

        // try verify the MACs
        let verify_mac = HandshakeInit::verify(
            init_msg,
            &self.config.static_,
            overload,
            &state.cookie,
            addr,
        )?;
        let init_msg = match verify_mac {
            // macs are valid
            ControlFlow::Continue(msg) => msg,
            // the mac1 was valid, but we need a valid mac2 as well.
            ControlFlow::Break(cookie) => {
                // cookie message is always smaller than the initial message
                return Ok(self.write_cookie_message(
                    init_msg.mac1,
                    init_msg.sender.get(),
                    cookie,
                    msg,
                ));
            }
        };

        // start new handshake state.
        let mut hs = HandshakeState::default();

        let data =
            async_decrypt_handshake_init(init_msg, &mut hs, &mut self.config.static_).await?;

        unsafe_log!("payload decrypted");
        // check if we know this peer
        let peer_idx = self
            .config
            .get_peer_idx(&data.static_key())
            .ok_or(Error::Rejected)?;
        let peer_config = &self.config.peers[peer_idx];
        let peer = &mut state.peers[peer_idx];

        unsafe_log!("peer id: {peer_idx:?}");
        // check for potential replay attack
        if *data.timestamp() < peer.latest_ts {
            return Err(Error::Rejected);
        }
        peer.latest_ts = *data.timestamp();

        // start a new session
        let vacant = allocate_session!(state);
        let session_id = *vacant.key();

        // complete handshake
        let esk_r = EphemeralPrivateKey::generate(&mut state.rng);

        let response = encrypt_handshake_resp(
            &mut hs,
            data,
            &esk_r,
            peer_config,
            session_id,
            peer.cookie.as_ref(),
        )?;
        peer.last_sent_mac1 = response.mac1;

        peer.current_transport = Some(session_id);

        // generate the encryption keys
        let (encrypt, decrypt) = hs.split::<CryptoCore>(false);
        let transport = SessionTransport {
            receiver: init_msg.sender.get(),
            encrypt,
            decrypt,
        };
        let session = Session {
            peer: peer_idx,
            started: state.now,
            sent: state.now,
            state: SessionState::Transport(transport),
            keepalive_pending: false,
        };

        vacant.insert(Box::new(session));

        // schedule key expiration
        state.timers.push(TimerEntry {
            time: state.now + REJECT_AFTER_TIME,
            kind: TimerEntryType::ExpireTransport { session_id },
        });

        // response message is always smaller than the initial message
        Ok(write_msg(msg, &response))
    }

    #[inline(never)]
    pub(crate) async fn async_handle_handshake_resp<'m>(
        &mut self,
        addr: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<Message<'m>, Error> {
        let state = &mut self.dynamic;

        unsafe_log!("[{addr:?}] parsed as handshake resp packet");
        let resp_msg = HandshakeResp::mut_from_bytes(msg).map_err(|_| Error::InvalidMessage)?;

        let overload = state.overloaded(addr.ip());
        let resp_msg = match HandshakeResp::verify(
            resp_msg,
            &self.config.static_,
            overload,
            &state.cookie,
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
        let session = match state.peers_by_session.entry(session_id) {
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
        let peer_config = &self.config.peers[session.peer];
        let peer = &mut state.peers[session.peer];

        async_decrypt_handshake_resp(
            resp_msg,
            &mut hs.state,
            &mut self.config.static_,
            peer_config,
            &hs.esk_i,
        )
        .await?;

        let hs_session = peer.current_handshake.take();
        debug_assert_eq!(hs_session, Some(session_id));
        peer.current_transport = Some(session_id);

        peer.endpoint = Some(addr);

        let (encrypt, decrypt) = hs.state.split::<CryptoCore>(true);
        hs.zeroize();

        session.state = SessionState::Transport(SessionTransport {
            receiver: resp_msg.sender.get(),
            encrypt,
            decrypt,
        });
        session.started = state.now;
        session.sent = state.now;

        // schedule re-key as we were the initiator
        state.timers.push(TimerEntry {
            time: state.now + REKEY_AFTER_TIME,
            kind: TimerEntryType::RekeyAttempt { session_id },
        });
        // schedule key expiration
        state.timers.push(TimerEntry {
            time: state.now + REJECT_AFTER_TIME,
            kind: TimerEntryType::ExpireTransport { session_id },
        });

        Ok(Message::HandshakeComplete(MessageEncrypter(session_id)))
    }
}

impl<O> Sessions<O> {
    #[inline(never)]
    pub(crate) fn handle_cookie(&mut self, msg: &mut [u8]) -> Result<(), Error> {
        let state = &mut self.dynamic;

        unsafe_log!("parsed as cookie packet");
        let cookie_msg = CookieMessage::mut_from_bytes(msg).map_err(|_| Error::InvalidMessage)?;

        let session = state
            .peers_by_session
            .get(&cookie_msg.receiver.get())
            .ok_or(Error::Rejected)?;
        let peer_config = &self.config.peers[session.peer];
        let peer = &mut state.peers[session.peer];

        let cookie = decrypt_cookie(
            &mut cookie_msg.cookie,
            &peer_config.cookie_key,
            &cookie_msg.nonce,
            &peer.last_sent_mac1,
        )?;

        peer.cookie = Some(*cookie);

        Ok(())
    }
}

pub(crate) async fn async_new_handshake<O: AsyncDhOracle>(
    sessions: &mut Sessions<O>,
    peer_idx: PeerId,
) -> Result<HandshakeInit, Error> {
    let state = &mut sessions.dynamic;
    let peer_config = &sessions.config.peers[peer_idx];
    let peer = &mut state.peers[peer_idx];

    let old_handshake = peer
        .current_handshake
        .and_then(|session| state.peers_by_session.remove(&session));

    // start a new session
    let vacant = allocate_session!(state);
    let sender = *vacant.key();
    peer.current_handshake = Some(sender);

    let esk_i = EphemeralPrivateKey::generate(&mut state.rng);
    let handshake = SessionHandshake {
        esk_i,
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
            keepalive_pending: false,
        }),
    };

    let session_id = *vacant.key();
    let session = vacant.insert(session);
    let SessionState::Handshake(handshake) = &mut session.state else {
        unreachable!()
    };

    let msg = rustyguard_crypto::async_encrypt_handshake_init(
        &mut handshake.state,
        &mut sessions.config.static_,
        peer_config,
        &handshake.esk_i,
        state.now,
        sender,
        peer.cookie.as_ref(),
    )
    .await?;

    state.timers.push(TimerEntry {
        time: state.now + REKEY_TIMEOUT,
        kind: TimerEntryType::InitAttempt { session_id },
    });
    // Bound the lifetime of the handshake-state session: if it never
    // completes, ExpireHandshake removes it after REKEY_ATTEMPT_TIME so
    // that abandoned handshakes don't leak in peers_by_session forever.
    state.timers.push(TimerEntry {
        time: state.now + REKEY_ATTEMPT_TIME,
        kind: TimerEntryType::ExpireHandshake { session_id },
    });

    Ok(msg)
}
