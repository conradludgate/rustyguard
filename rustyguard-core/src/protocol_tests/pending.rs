use super::*;
use rustyguard_crypto::SharedSecret;

fn limited_pair() -> (Sessions, Sessions, PeerId, PeerId) {
    let mut client_cfg = Config::new(CryptoCore::x25519_pubkey(&StaticPrivateKey([1; 32])))
        .with_max_pending_handshakes(1);
    let mut server_cfg = Config::new(CryptoCore::x25519_pubkey(&StaticPrivateKey([2; 32])))
        .with_max_pending_handshakes(1);
    let cp = client_cfg.insert_peer(StaticPeerConfig::new(
        PublicKey(server_cfg.public_key.0),
        None,
        Some(SERVER_ADDR.parse().unwrap()),
    ));
    let sp = server_cfg.insert_peer(StaticPeerConfig::new(
        PublicKey(client_cfg.public_key.0),
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

fn start(client: &mut Sessions, peer: PeerId) -> Handshake<CryptoCore> {
    match client.send_message(peer, &mut [0; 16]).unwrap() {
        SendMessage::Handshake(work) => *work,
        _ => panic!("expected caller-managed DH"),
    }
}

fn secret(work: &Handshake<CryptoCore>, key: u8) -> SharedSecret {
    SharedSecret::new(CryptoCore::x25519(&StaticPrivateKey([key; 32]), &work.peer_key()).unwrap())
        .unwrap()
}

fn finish(sessions: &Sessions, mut work: Handshake<CryptoCore>, key: u8) -> Event {
    loop {
        let agreement = secret(&work, key);
        match work.complete(sessions, agreement).unwrap() {
            Event::Handshake(next) => work = next,
            result => return result,
        }
    }
}

fn write(event: Event) -> MaintenanceMsg {
    match event {
        Event::Write(message) => message,
        _ => panic!("expected write"),
    }
}

fn receive(
    sessions: &mut Sessions,
    message: &MaintenanceMsg,
    source: &str,
) -> Handshake<CryptoCore> {
    let mut packet = Packet([0; 256]);
    packet.0[..message.data().len()].copy_from_slice(message.data());
    match sessions
        .recv_message(
            source.parse().unwrap(),
            &mut packet.0[..message.data().len()],
        )
        .unwrap()
    {
        Message::Handshake(work) => *work,
        _ => panic!("expected caller-managed DH"),
    }
    // Packet storage is gone before the caller supplies the agreement.
}

#[tokio::test(flavor = "current_thread")]
async fn established_traffic_continues_while_rekey_dh_is_pending() {
    use std::rc::Rc;
    let (mut client, mut server, cp, sp) = limited_pair();
    let work = start(&mut client, cp);
    let initiation = write(finish(&client, work, 1));
    let work = receive(&mut server, &initiation, CLIENT_ADDR);
    let response = write(finish(&server, work, 2));
    let work = receive(&mut client, &response, SERVER_ADDR);
    assert!(matches!(
        finish(&client, work, 1),
        Event::HandshakeComplete(_)
    ));

    let mut rng = StdRng::seed_from_u64(456);
    let now = Tai64N(Tai64(1121), 0);
    server.turn(now, &mut rng);
    client.config.max_pending_handshakes = 0;
    assert!(client.turn(now, &mut rng).is_none());
    client.config.max_pending_handshakes = 1;
    let now = Tai64N(Tai64(1127), 0);
    let work = match client.turn(now, &mut rng).unwrap() {
        Event::Handshake(work) => work,
        _ => panic!("expected rekey DH"),
    };
    // No duplicate rekey job.
    assert!(client.turn(now, &mut rng).is_none());
    // A caller-owned !Send key and a device future that cannot finish yet.
    let key = Rc::new(StaticPrivateKey([1; 32]));
    let (resume, paused) = tokio::sync::oneshot::channel();
    let agreement = async move {
        paused.await.unwrap();
        let secret =
            SharedSecret::new(CryptoCore::x25519(&key, &work.peer_key()).unwrap()).unwrap();
        (work, secret)
    };
    tokio::pin!(agreement);
    tokio::select! {
        biased;
        _ = &mut agreement => panic!("device must still be pending"),
        _ = tokio::task::yield_now() => {}
    }
    exchange_data(&mut client, cp, &mut server, CLIENT_ADDR);
    exchange_data(&mut server, sp, &mut client, SERVER_ADDR);
    resume.send(()).unwrap();
    let (work, secret) = agreement.await;
    let initiation = write(work.complete(&client, secret).unwrap());
    let work = receive(&mut server, &initiation, CLIENT_ADDR);
    let response = write(finish(&server, work, 2));
    let work = receive(&mut client, &response, SERVER_ADDR);
    assert!(matches!(
        finish(&client, work, 1),
        Event::HandshakeComplete(_)
    ));
    exchange_data(&mut client, cp, &mut server, CLIENT_ADDR);
    exchange_data(&mut server, sp, &mut client, SERVER_ADDR);
}

#[test]
fn dropping_or_expiring_work_releases_capacity_and_late_results_are_rejected() {
    let (mut client, _, cp, _) = limited_pair();
    let work = start(&mut client, cp);
    assert!(matches!(
        client.send_message(cp, &mut [0; 16]),
        Err(Error::HandshakeLimit)
    ));
    drop(work);
    let work = start(&mut client, cp);
    let mut rng = StdRng::seed_from_u64(456);
    // Exact deadline, without needing the strictly-later timer to run.
    client.turn(Tai64N(Tai64(1090), 0), &mut rng);
    let agreement = secret(&work, 1);
    assert!(matches!(
        work.complete(&client, agreement),
        Err(Error::Rejected)
    ));
    client.turn(Tai64N(Tai64(1090), 1), &mut rng);
    let old = start(&mut client, cp);
    client.turn(Tai64N(Tai64(1180), 1), &mut rng);
    client.turn(Tai64N(Tai64(1180), 2), &mut rng);
    let current = start(&mut client, cp);
    let agreement = secret(&old, 1);
    assert!(matches!(
        old.complete(&client, agreement),
        Err(Error::Rejected)
    ));
    assert!(matches!(finish(&client, current, 1), Event::Write(_)));
}

#[test]
fn work_is_tied_to_its_engine_and_outgoing_handshake_generation() {
    let (mut client, mut server, cp, _) = limited_pair();
    client.config.max_pending_handshakes = 2;
    let old = start(&mut client, cp);
    let current = start(&mut client, cp);
    let agreement = secret(&old, 1);
    assert!(matches!(
        old.complete(&client, agreement),
        Err(Error::Rejected)
    ));
    let initiation = write(finish(&client, current, 1));
    let work = receive(&mut server, &initiation, CLIENT_ADDR);
    let response = write(finish(&server, work, 2));
    let old = receive(&mut client, &response, SERVER_ADDR);
    // Reuse the exact session ID for a replacement to exercise generation checks,
    // rather than relying on the random wire ID never colliding.
    let id = client.dynamic.borrow().peers[cp].current_handshake.unwrap();
    client
        .dynamic
        .borrow_mut()
        .peers_by_session
        .get_mut(&id)
        .unwrap()
        .state = SessionState::Handshake(SessionHandshake {
        esk_i: EphemeralPrivateKey::generate(&mut StdRng::seed_from_u64(999)),
        state: Some(HandshakeState::default()),
        generation: u64::MAX,
    });
    let agreement = secret(&old, 1);
    assert!(matches!(
        old.complete(&client, agreement),
        Err(Error::Rejected)
    ));
    let work = start(&mut client, cp);
    let agreement = secret(&work, 1);
    assert!(matches!(
        work.complete(&server, agreement),
        Err(Error::Rejected)
    ));
}

#[test]
fn admission_precedes_pending_work_and_cancellation_does_not_authenticate() {
    let (mut client, mut server, cp, sp) = limited_pair();
    let work = start(&mut client, cp);
    let initiation = write(finish(&client, work, 1));
    let mut packet = Packet([0; 256]);
    let bytes = initiation.data();
    packet.0[..bytes.len()].copy_from_slice(bytes);
    packet.0[bytes.len() - 32] ^= 1; // MAC1
    assert!(server
        .recv_message(CLIENT_ADDR.parse().unwrap(), &mut packet.0[..bytes.len()])
        .is_err());
    assert!(server.dynamic.borrow().pending_handshakes.is_empty());
    let work = receive(&mut server, &initiation, CLIENT_ADDR);
    assert!(server.dynamic.borrow().peers[sp]
        .current_transport
        .is_none());
    drop(work); // Also models a device failure, without supplying a result.
    assert!(server.dynamic.borrow().peers_by_session.is_empty());
    let work = receive(&mut server, &initiation, CLIENT_ADDR);
    let agreement = secret(&work, 2);
    let work = match work.complete(&server, agreement).unwrap() {
        Event::Handshake(work) => work,
        _ => panic!("timestamp DH"),
    };
    drop(work);
    assert!(server.dynamic.borrow().peers_by_session.is_empty());
    let work = receive(&mut server, &initiation, CLIENT_ADDR);
    assert!(matches!(finish(&server, work, 2), Event::Write(_)));
}

#[test]
fn incoming_work_expires_at_either_suspension_point() {
    for second_step in [false, true] {
        let (mut client, mut server, cp, _) = limited_pair();
        let work = start(&mut client, cp);
        let initiation = write(finish(&client, work, 1));
        let mut work = receive(&mut server, &initiation, CLIENT_ADDR);
        if second_step {
            let agreement = secret(&work, 2);
            work = match work.complete(&server, agreement).unwrap() {
                Event::Handshake(next) => next,
                _ => panic!("expected timestamp agreement"),
            };
        }
        server.turn(Tai64N(Tai64(1090), 0), &mut StdRng::seed_from_u64(456));
        let agreement = secret(&work, 2);
        assert!(matches!(
            work.complete(&server, agreement),
            Err(Error::Rejected)
        ));
        assert!(server.dynamic.borrow().peers_by_session.is_empty());
    }
}

#[test]
fn cancelling_a_response_candidate_preserves_the_original_handshake() {
    let (mut client, mut server, cp, sp) = limited_pair();
    let work = start(&mut client, cp);
    let initiation = write(finish(&client, work, 1));
    let work = receive(&mut server, &initiation, CLIENT_ADDR);
    let response = write(finish(&server, work, 2));
    let work = receive(&mut client, &response, SERVER_ADDR);
    drop(work);
    let work = receive(&mut client, &response, SERVER_ADDR);
    assert!(matches!(
        finish(&client, work, 1),
        Event::HandshakeComplete(_)
    ));
    exchange_data(&mut client, cp, &mut server, CLIENT_ADDR);
    exchange_data(&mut server, sp, &mut client, SERVER_ADDR);
    assert!(client
        .dynamic
        .borrow()
        .pending_handshakes
        .iter()
        .all(|job| job.strong_count() == 0));
}

#[test]
fn cookie_challenges_do_not_reserve_device_work() {
    let (mut client, mut server, cp, _) = limited_pair();
    let work = start(&mut client, cp);
    let initiation = write(finish(&client, work, 1));
    for _ in 0..10 {
        server
            .dynamic
            .borrow_mut()
            .overloaded(CLIENT_ADDR.parse::<SocketAddr>().unwrap().ip());
    }
    let mut packet = Packet([0; 256]);
    packet.0[..initiation.data().len()].copy_from_slice(initiation.data());
    assert!(matches!(
        server.recv_message(
            CLIENT_ADDR.parse().unwrap(),
            &mut packet.0[..initiation.data().len()]
        ),
        Ok(Message::Write(_))
    ));
    assert!(server.dynamic.borrow().pending_handshakes.is_empty());
}
