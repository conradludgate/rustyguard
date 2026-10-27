use super::*;
use rand::{rngs::StdRng, SeedableRng};
use rustyguard_crypto::{encrypt_handshake_init, CryptoPrimatives};

const CLIENT_ADDR: &str = "127.0.0.1:1000";
const SERVER_ADDR: &str = "127.0.0.1:2000";

#[repr(align(16))]
struct Packet([u8; 256]);

fn pair() -> (Sessions, Sessions, PeerId, PeerId) {
    let client_key = StaticPrivateKey([1; 32]);
    let server_key = StaticPrivateKey([2; 32]);
    let client_pk = CryptoCore::x25519_pubkey(&client_key);
    let server_pk = CryptoCore::x25519_pubkey(&server_key);
    let mut client_cfg = Config::new(client_key);
    let mut server_cfg = Config::new(server_key);
    let cp = client_cfg.insert_peer(StaticPeerConfig::new(
        server_pk,
        None,
        Some(SERVER_ADDR.parse().unwrap()),
    ));
    let sp = server_cfg.insert_peer(StaticPeerConfig::new(
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

fn exchange_data(sender: &mut Sessions, peer: PeerId, receiver: &mut Sessions, source: &str) {
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

#[test]
fn identical_initiation_replay_preserves_established_transport() {
    let (mut client, mut server, cp, sp) = pair();
    let initiation = match client.send_message(cp, &mut [0; 16]).unwrap() {
        SendMessage::Maintenance(message) => message.data().to_vec(),
        _ => panic!("expected initiation"),
    };
    let mut packet = Packet([0; 256]);
    packet.0[..initiation.len()].copy_from_slice(&initiation);
    let response = match server
        .recv_message(
            CLIENT_ADDR.parse().unwrap(),
            &mut packet.0[..initiation.len()],
        )
        .unwrap()
    {
        Message::Write(response) => response,
        _ => panic!("expected handshake response"),
    };
    assert!(matches!(
        client.recv_message(SERVER_ADDR.parse().unwrap(), response),
        Ok(Message::HandshakeComplete(_))
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
            server.recv_message(
                CLIENT_ADDR.parse().unwrap(),
                &mut packet.0[..initiation.len()]
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
        let initiation = encrypt_handshake_init(
            &mut HandshakeState::default(),
            &client.config.static_,
            &client.config.peers[cp],
            &EphemeralPrivateKey::generate(&mut rng),
            Tai64N(Tai64(seconds), 0),
            42,
            None,
        )
        .unwrap();
        let mut packet = Packet([0; 256]);
        let bytes = initiation.as_bytes();
        packet.0[..bytes.len()].copy_from_slice(bytes);
        let old_transport = server.dynamic.borrow().peers[sp].current_transport;
        let result =
            server.recv_message(CLIENT_ADDR.parse().unwrap(), &mut packet.0[..bytes.len()]);
        if accepted {
            assert!(matches!(result, Ok(Message::Write(_))));
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
