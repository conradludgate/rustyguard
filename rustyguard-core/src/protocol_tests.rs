use super::*;
use rand::{rngs::StdRng, SeedableRng};
use rustyguard_crypto::{CryptoPrimatives, EncryptHandshakeInit, SharedSecret};

const CLIENT_ADDR: &str = "127.0.0.1:1000";
const SERVER_ADDR: &str = "127.0.0.1:2000";

#[test]
fn invalid_response_preserves_the_outstanding_handshake() {
    use rustyguard_crypto::HasMac;
    let (mut client, mut server, cp, sp) = pair();
    let initiation = start(&mut client, cp, &StaticPrivateKey([1; 32]))
        .data()
        .to_vec();
    let mut packet = Packet([0; 256]);
    packet.0[..initiation.len()].copy_from_slice(&initiation);
    let response = match receive_handshake(
        &mut server,
        CLIENT_ADDR.parse().unwrap(),
        &mut packet.0[..initiation.len()],
        &StaticPrivateKey([2; 32]),
    )
    .unwrap()
    {
        Event::Write(message) => message.data().to_vec(),
        _ => panic!("expected response"),
    };
    let mut invalid = rustyguard_types::HandshakeResp::read_from_bytes(&response).unwrap();
    invalid.empty.tag.0[0] ^= 1;
    invalid.mac1 = invalid.compute_mac1::<CryptoCore>(&client.config.mac1_key);
    let bytes = invalid.as_bytes();
    packet.0[..bytes.len()].copy_from_slice(bytes);
    assert!(matches!(
        receive_handshake(
            &mut client,
            SERVER_ADDR.parse().unwrap(),
            &mut packet.0[..bytes.len()],
            &StaticPrivateKey([1; 32])
        ),
        Err(Error::DecryptionError)
    ));
    packet.0[..response.len()].copy_from_slice(&response);
    assert!(matches!(
        receive_handshake(
            &mut client,
            SERVER_ADDR.parse().unwrap(),
            &mut packet.0[..response.len()],
            &StaticPrivateKey([1; 32])
        ),
        Ok(Event::HandshakeComplete(_))
    ));
    exchange_data(&mut client, cp, &mut server, CLIENT_ADDR);
    exchange_data(&mut server, sp, &mut client, SERVER_ADDR);
}

#[repr(align(16))]
struct Packet([u8; 256]);

fn pair() -> (Sessions, Sessions, PeerId, PeerId) {
    pair_with::<CryptoCore, CryptoCore>()
}

fn pair_with<C: CryptoPrimatives, S: CryptoPrimatives>(
) -> (Sessions<C>, Sessions<S>, PeerId, PeerId) {
    let client_key = StaticPrivateKey([1; 32]);
    let server_key = StaticPrivateKey([2; 32]);
    let client_pk = C::x25519_pubkey(&client_key);
    let server_pk = S::x25519_pubkey(&server_key);
    let mut client_cfg = Config::<C>::with_crypto(PublicKey(client_pk.0));
    let mut server_cfg = Config::<S>::with_crypto(PublicKey(server_pk.0));
    let cp = client_cfg.insert_peer(StaticPeerConfig::with_crypto::<C>(
        server_pk,
        None,
        Some(SERVER_ADDR.parse().unwrap()),
    ));
    let sp = server_cfg.insert_peer(StaticPeerConfig::with_crypto::<S>(
        client_pk,
        None,
        Some(CLIENT_ADDR.parse().unwrap()),
    ));
    let mut rng = StdRng::seed_from_u64(123);
    let client = Sessions::new(client_cfg, &mut rng);
    let server = Sessions::new(server_cfg, &mut rng);
    client.turn(Tai64N(Tai64(1000), 0), &mut rng);
    server.turn(Tai64N(Tai64(1000), 0), &mut rng);
    (client, server, cp, sp)
}

fn exchange_data<C: CryptoPrimatives, S: CryptoPrimatives>(
    sender: &mut Sessions<C>,
    peer: PeerId,
    receiver: &mut Sessions<S>,
    source: &str,
) {
    let mut payload = *b"Hello, World!\0\0\0";
    let metadata = match sender.send_message(peer, &mut payload).unwrap() {
        SendMessage::Data(_, metadata) => metadata,
        _ => panic!("expected established transport"),
    };
    let mut packet = Packet([0; 256]);
    packet.0[..16].copy_from_slice(metadata.header.as_bytes());
    packet.0[16..32].copy_from_slice(&payload);
    packet.0[32..48].copy_from_slice(&metadata.tag.0);
    match receiver
        .recv_message(source.parse().unwrap(), &mut packet.0[..48])
        .unwrap()
    {
        Message::Read(_, plaintext) => assert_eq!(plaintext, b"Hello, World!\0\0\0"),
        _ => panic!("expected transport data"),
    }
}

#[cfg(all(feature = "graviola", feature = "rustcrypto"))]
#[test]
fn mixed_provider_peers_exchange_handshakes_cookies_and_data() {
    use rustyguard_crypto::providers::{Graviola, RustCrypto};
    mixed_provider_pair::<Graviola, RustCrypto>();
    mixed_provider_pair::<RustCrypto, Graviola>();
}

fn mixed_provider_pair<C: CryptoPrimatives, S: CryptoPrimatives>() {
    let (mut client, mut server, cp, sp) = pair_with::<C, S>();
    let initiation = start(&mut client, cp, &StaticPrivateKey([1; 32]))
        .data()
        .to_vec();
    // Force the next initiation through the cookie path before doing DH.
    for _ in 0..10 {
        server
            .dynamic
            .borrow_mut()
            .overloaded(CLIENT_ADDR.parse::<SocketAddr>().unwrap().ip());
    }
    let mut packet = Packet([0; 256]);
    packet.0[..initiation.len()].copy_from_slice(&initiation);
    let cookie = match server
        .recv_message(
            CLIENT_ADDR.parse().unwrap(),
            &mut packet.0[..initiation.len()],
        )
        .unwrap()
    {
        Message::Write(reply) => reply.to_vec(),
        _ => panic!("expected cookie challenge"),
    };
    packet.0[..cookie.len()].copy_from_slice(&cookie);
    assert!(matches!(
        client.recv_message(SERVER_ADDR.parse().unwrap(), &mut packet.0[..cookie.len()]),
        Ok(Message::Noop)
    ));

    let mut retry = initiation;
    let mut init = HandshakeInit::read_from_bytes(&retry).unwrap();
    use rustyguard_crypto::HasMac;
    init.mac2 = init.compute_mac2::<C>(client.dynamic.borrow().peers[cp].cookie.as_ref().unwrap());
    retry.copy_from_slice(init.as_bytes());
    packet.0[..retry.len()].copy_from_slice(&retry);
    let response = match receive_handshake(
        &mut server,
        CLIENT_ADDR.parse().unwrap(),
        &mut packet.0[..retry.len()],
        &StaticPrivateKey([2; 32]),
    )
    .unwrap()
    {
        Event::Write(reply) => reply,
        _ => panic!("expected handshake response"),
    };
    packet.0[..response.data().len()].copy_from_slice(response.data());
    assert!(matches!(
        receive_handshake(
            &mut client,
            SERVER_ADDR.parse().unwrap(),
            &mut packet.0[..response.data().len()],
            &StaticPrivateKey([1; 32])
        ),
        Ok(Event::HandshakeComplete(_))
    ));
    exchange_data(&mut client, cp, &mut server, CLIENT_ADDR);
    exchange_data(&mut server, sp, &mut client, SERVER_ADDR);
}

#[test]
fn custom_provider_is_used_for_protocol_operations() {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use rustyguard_crypto::{CryptoError, Key, Mac, PublicKey};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    struct Traced;
    macro_rules! forward {
        ($bit:expr, $name:ident($($arg:ident: $ty:ty),* $(,)?) -> $out:ty) => {
            fn $name($($arg: $ty),*) -> $out {
                CALLS.fetch_or(1 << $bit, Ordering::Relaxed);
                CryptoCore::$name($($arg),*)
            }
        };
    }
    impl CryptoPrimatives for Traced {
        forward!(0, blake2s_hash(left: &[u8], right: &[u8]) -> Key);
        forward!(1, blake2s_mac(key: &[u8], msg: &[u8]) -> Mac);
        forward!(2, hmac_blake2s(key: &Key, msg: &[u8]) -> Key);
        fn hkdf_blake2s<const N: usize>(key: &mut Key, msg: &[u8], output: &mut [Key; N]) {
            CALLS.fetch_or(1 << 3, Ordering::Relaxed);
            CryptoCore::hkdf_blake2s(key, msg, output);
        }
        forward!(
            4,
            x25519(secret: &StaticPrivateKey, public: &PublicKey) -> Result<Key, CryptoError>
        );
        forward!(5, x25519_pubkey(secret: &StaticPrivateKey) -> PublicKey);
        forward!(
            6,
            chacha20poly1305_enc(
                key: &Key,
                nonce: &[u8; 12],
                aad: &[u8],
                payload: &mut [u8],
                tag: &mut [u8; 16],
            ) -> ()
        );
        forward!(
            7,
            chacha20poly1305_dec(
                key: &Key,
                nonce: &[u8; 12],
                aad: &[u8],
                payload: &mut [u8],
                tag: &[u8; 16],
            ) -> Result<(), CryptoError>
        );
        forward!(
            8,
            xchacha20poly1305_enc(
                key: &Key,
                nonce: &[u8; 24],
                aad: &[u8],
                payload: &mut [u8],
                tag: &mut [u8; 16],
            ) -> ()
        );
        forward!(
            9,
            xchacha20poly1305_dec(
                key: &Key,
                nonce: &[u8; 24],
                aad: &[u8],
                payload: &mut [u8],
                tag: &[u8; 16],
            ) -> Result<(), CryptoError>
        );
    }

    mixed_provider_pair::<Traced, CryptoCore>();
    mixed_provider_pair::<CryptoCore, Traced>();
    // HMAC can be internal to the provider's HKDF implementation, rather than
    // called separately by the protocol. All other primitive hooks are exercised.
    let expected = 0x3ff & !(1 << 2);
    assert_eq!(CALLS.load(Ordering::Relaxed) & expected, expected);
}

#[test]
fn identical_initiation_replay_preserves_established_transport() {
    let (mut client, mut server, cp, sp) = pair();
    let initiation = start(&mut client, cp, &StaticPrivateKey([1; 32]))
        .data()
        .to_vec();
    let mut packet = Packet([0; 256]);
    packet.0[..initiation.len()].copy_from_slice(&initiation);
    let response = match receive_handshake(
        &mut server,
        CLIENT_ADDR.parse().unwrap(),
        &mut packet.0[..initiation.len()],
        &StaticPrivateKey([2; 32]),
    )
    .unwrap()
    {
        Event::Write(response) => response,
        _ => panic!("expected handshake response"),
    };
    packet.0[..response.data().len()].copy_from_slice(response.data());
    assert!(matches!(
        receive_handshake(
            &mut client,
            SERVER_ADDR.parse().unwrap(),
            &mut packet.0[..response.data().len()],
            &StaticPrivateKey([1; 32])
        ),
        Ok(Event::HandshakeComplete(_))
    ));
    exchange_data(&mut client, cp, &mut server, CLIENT_ADDR);
    exchange_data(&mut server, sp, &mut client, SERVER_ADDR);
    let before = {
        let state = server.dynamic.borrow();
        (
            state.peers[sp].current_transport,
            state.peers_by_session.len(),
            state.timers.len(),
            state.peers[sp].latest_ts,
        )
    };
    for _ in 0..2 {
        // recv_message decrypts in place, so replay the original wire bytes.
        packet.0[..initiation.len()].copy_from_slice(&initiation);
        assert!(matches!(
            receive_handshake(
                &mut server,
                CLIENT_ADDR.parse().unwrap(),
                &mut packet.0[..initiation.len()],
                &StaticPrivateKey([2; 32])
            ),
            Err(Error::Rejected)
        ));
        let state = server.dynamic.borrow();
        assert_eq!(
            (
                state.peers[sp].current_transport,
                state.peers_by_session.len(),
                state.timers.len(),
                state.peers[sp].latest_ts
            ),
            before
        );
        drop(state);
        exchange_data(&mut client, cp, &mut server, CLIENT_ADDR);
        exchange_data(&mut server, sp, &mut client, SERVER_ADDR);
    }
}

#[test]
fn initiation_timestamps_must_strictly_increase() {
    let (client, mut server, cp, sp) = pair();
    let mut rng = StdRng::seed_from_u64(456);
    for (seconds, accepted) in [(1000, true), (999, false), (1000, false), (1001, true)] {
        let request = EncryptHandshakeInit::<CryptoCore>::new(
            HandshakeState::default(),
            &client.config.public_key,
            &client.config.peers[cp],
            &EphemeralPrivateKey::generate(&mut rng),
            Tai64N(Tai64(seconds), 0),
            42,
            None,
        )
        .unwrap();
        let secret = SharedSecret::new(
            CryptoCore::x25519(&StaticPrivateKey([1; 32]), &request.peer_key()).unwrap(),
        )
        .unwrap();
        let (initiation, _) = request.complete(secret);
        let mut packet = Packet([0; 256]);
        let bytes = initiation.as_bytes();
        packet.0[..bytes.len()].copy_from_slice(bytes);
        let old_transport = server.dynamic.borrow().peers[sp].current_transport;
        let result = receive_handshake(
            &mut server,
            CLIENT_ADDR.parse().unwrap(),
            &mut packet.0[..bytes.len()],
            &StaticPrivateKey([2; 32]),
        );
        if accepted {
            assert!(matches!(result, Ok(Event::Write(_))));
            assert_ne!(
                server.dynamic.borrow().peers[sp].current_transport,
                old_transport
            );
        } else {
            assert!(matches!(result, Err(Error::Rejected)));
            assert_eq!(
                server.dynamic.borrow().peers[sp].current_transport,
                old_transport
            );
        }
    }
}

#[test]
fn rate_limit_survives_frequent_turns() {
    let (client, _, _, _) = pair();
    let ip = CLIENT_ADDR.parse::<core::net::SocketAddr>().unwrap().ip();
    for _ in 0..10 {
        assert!(!client.dynamic.borrow_mut().overloaded(ip));
    }
    let mut rng = StdRng::seed_from_u64(456);
    client.turn(Tai64N(Tai64(1000), 100_000_000), &mut rng);
    assert!(client.dynamic.borrow_mut().overloaded(ip));
}

#[test]
fn rate_limit_reset_tracks_each_window() {
    let (client, _, _, _) = pair();
    let mut rng = StdRng::seed_from_u64(789);
    let key = 123_u64;
    let mut count = 0;
    for (seconds, nanos, reset) in [
        (1000, 100_000_000, false),
        (1000, 999_999_999, false),
        // Preserve the existing strictly-more-than-one-second boundary.
        (1001, 0, false),
        (1001, 1, true),
        (1001, 1, false),
        (1001, 500_000_000, false),
        (1002, 1, false),
        (1002, 2, true),
        (1010, 0, true),
        (1009, 0, false),
    ] {
        client.turn(Tai64N(Tai64(seconds), nanos), &mut rng);
        count = if reset { 1 } else { count + 1 };
        assert_eq!(
            client.dynamic.borrow_mut().ip_rate_limit.count(&key),
            count,
            "at {seconds}:{nanos}"
        );
    }
}

#[test]
fn incoming_counter_limit_preserves_transport_state() {
    let (_, mut server, _, sp) = pair();
    let key = [42; 32];
    let session_id = 42;
    {
        let mut state = server.dynamic.borrow_mut();
        let now = state.now;
        state.peers_by_session.insert(
            session_id,
            Box::new(Session {
                peer: sp,
                started: now,
                sent: now,
                state: SessionState::Transport(SessionTransport {
                    receiver: 123,
                    encrypt: EncryptionKey::new(key),
                    decrypt: DecryptionKey::new(key),
                }),
                keepalive_pending: false,
            }),
        );
        state.peers[sp].current_transport = Some(session_id);
    }
    let source = "127.0.0.1:9999".parse().unwrap();
    for counter in [
        REJECT_AFTER_MESSAGES,
        REJECT_AFTER_MESSAGES + 1,
        u64::MAX,
        0,
        REJECT_AFTER_MESSAGES - 1,
    ] {
        let mut packet = Packet([0; 256]);
        let header = DataHeader {
            _type: little_endian::U32::new(MSG_DATA),
            receiver: little_endian::U32::new(session_id),
            counter: little_endian::U64::new(counter),
        };
        packet.0[..16].copy_from_slice(header.as_bytes());
        packet.0[16..32].copy_from_slice(b"Hello, World!\0\0\0");
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        let (payload, tag) = packet.0[16..48].split_at_mut(16);
        CryptoCore::chacha20poly1305_enc(&key, &nonce, &[], payload, tag.try_into().unwrap());
        let original = packet.0;
        let result = server.recv_message(source, &mut packet.0[..48]);
        if counter >= REJECT_AFTER_MESSAGES {
            assert!(matches!(result, Err(Error::Rejected)), "counter {counter}");
            assert_eq!(packet.0, original, "rejected packet must not be decrypted");
            assert_eq!(
                server.dynamic.borrow().peers[sp].endpoint,
                Some(CLIENT_ADDR.parse().unwrap())
            );
        } else {
            match result {
                Ok(Message::Read(peer, payload)) => {
                    assert_eq!(peer, sp);
                    assert_eq!(payload, b"Hello, World!\0\0\0");
                }
                _ => panic!("valid packet rejected after over-limit packet"),
            }
        }
    }
    assert_eq!(
        server.dynamic.borrow().peers[sp].current_transport,
        Some(session_id)
    );
}

// Application-side drivers used by the software-key regression fixtures. Core
// only sees public keys and the same owned work used by the delayed-key test.
pub(super) fn finish<C: CryptoPrimatives>(
    sessions: &Sessions<C>,
    key: &StaticPrivateKey,
    mut work: Handshake<C>,
) -> Result<Event<C>, Error> {
    loop {
        let secret = SharedSecret::new(C::x25519(key, &work.peer_key())?)?;
        match work.complete(sessions, secret)? {
            Event::Handshake(next) => work = next,
            event => return Ok(event),
        }
    }
}

pub(super) fn start<C: CryptoPrimatives>(
    sessions: &mut Sessions<C>,
    peer: PeerId,
    key: &StaticPrivateKey,
) -> MaintenanceMsg {
    let SendMessage::Handshake(work) = sessions.send_message(peer, &mut [0; 16]).unwrap() else {
        panic!("expected DH work")
    };
    let Event::Write(message) = finish(sessions, key, *work).unwrap() else {
        panic!("expected initiation")
    };
    message
}

pub(super) fn receive_handshake<C: CryptoPrimatives>(
    sessions: &mut Sessions<C>,
    addr: SocketAddr,
    packet: &mut [u8],
    key: &StaticPrivateKey,
) -> Result<Event<C>, Error> {
    let Message::Handshake(work) = sessions.recv_message(addr, packet)? else {
        panic!("expected DH work")
    };
    finish(sessions, key, *work)
}

mod pending;
