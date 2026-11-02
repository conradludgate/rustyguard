#![cfg(any(feature = "graviola", feature = "rustcrypto"))]

use rand::{rngs::StdRng, SeedableRng};
use rustyguard_core::{Config, Event, Message, SendMessage, Sessions, StaticPrivateKey, Tai64N};
use rustyguard_crypto::{CryptoCore, CryptoPrimatives, SharedSecret, StaticPeerConfig};
use tai64::Tai64;

#[repr(align(16))]
struct Packet([u8; 256]);

#[test]
fn overloaded_receivers_cookie_is_accepted_by_the_initiator() {
    let mut rng = StdRng::seed_from_u64(123);
    let server_key = StaticPrivateKey([2; 32]);
    let client_key = StaticPrivateKey([1; 32]);
    let mut config = Config::new(CryptoCore::x25519_pubkey(&client_key));
    let peer = config.insert_peer(StaticPeerConfig::new(
        CryptoCore::x25519_pubkey(&server_key),
        None,
        Some("127.0.0.1:2000".parse().unwrap()),
    ));
    let mut client = Sessions::new(config, &mut rng);
    let mut server = Sessions::new(
        Config::new(CryptoCore::x25519_pubkey(&server_key)),
        &mut rng,
    );
    client.turn(Tai64N(Tai64(1000), 0), &mut rng);
    let init = match client.send_message(peer, &mut [0; 16]).unwrap() {
        SendMessage::Handshake(work) => {
            let secret =
                SharedSecret::new(CryptoCore::x25519(&client_key, &work.peer_key()).unwrap())
                    .unwrap();
            match work.complete(&client, secret).unwrap() {
                Event::Write(message) => message.data().to_vec(),
                _ => panic!("expected initiation"),
            }
        }
        _ => panic!("expected initiation"),
    };
    let source = "127.0.0.1:1000".parse().unwrap();
    let mut packet = Packet([0; 256]);
    for _ in 0..10 {
        packet.0[..init.len()].copy_from_slice(&init);
        // The client is not a configured peer, but its MAC1 is valid.
        let Message::Handshake(work) = server
            .recv_message(source, &mut packet.0[..init.len()])
            .unwrap()
        else {
            panic!("expected DH work")
        };
        let secret =
            SharedSecret::new(CryptoCore::x25519(&server_key, &work.peer_key()).unwrap()).unwrap();
        assert!(work.complete(&server, secret).is_err());
    }
    packet.0[..init.len()].copy_from_slice(&init);
    let reply = match server
        .recv_message(source, &mut packet.0[..init.len()])
        .unwrap()
    {
        Message::Write(reply) => reply,
        _ => panic!("expected cookie challenge"),
    };
    assert!(matches!(
        client
            .recv_message("127.0.0.1:2000".parse().unwrap(), reply)
            .unwrap(),
        Message::Noop
    ));
}
