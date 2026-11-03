use core::net::SocketAddr;

use divan::{black_box, Bencher};
use rand::{rng, rngs::ThreadRng, RngCore};
use rustyguard_core::{Event, Handshake, PublicKey, StaticPrivateKey, Tai64N};
use rustyguard_crypto::{CryptoCore, CryptoPrimatives, Key, SharedSecret, StaticPeerConfig};
use tai64::Tai64;
use zerocopy::IntoBytes;

use rustyguard_core::{Config, PeerId, Sessions};

fn main() {
    divan::main()
}

fn session_with_peer(
    secret_key: StaticPrivateKey,
    peer_public_key: PublicKey,
    preshared_key: Key,
    endpoint: SocketAddr,
) -> (Sessions, PeerId, StaticPrivateKey) {
    let peer = StaticPeerConfig::new(peer_public_key, Some(preshared_key), Some(endpoint));
    let mut config = Config::new(CryptoCore::x25519_pubkey(&secret_key));
    let id = config.insert_peer(peer);
    let sessions = Sessions::new(config, &mut rng());
    // Timestamp zero is the initial replay floor; real callers advance time.
    sessions.turn(Tai64N(Tai64(1), 0), &mut rng());
    (sessions, id, secret_key)
}

#[repr(align(16))]
struct AlignedPacket([u8; 256]);

fn gen_sk(r: &mut ThreadRng) -> StaticPrivateKey {
    let mut b = [0u8; 32];
    r.fill_bytes(&mut b);
    StaticPrivateKey(b)
}

#[divan::bench(sample_count = 100, sample_size = 100)]
fn roundtrip(b: Bencher) {
    let server_addr: SocketAddr = "10.0.1.1:1234".parse().unwrap();
    let client_addr: SocketAddr = "10.0.2.1:1234".parse().unwrap();

    b.with_inputs(|| {
        let ssk_i = gen_sk(&mut rng());
        let ssk_r = gen_sk(&mut rng());
        let spk_i = CryptoCore::x25519_pubkey(&ssk_i);
        let spk_r = CryptoCore::x25519_pubkey(&ssk_r);
        let mut psk = Key::default();
        rng().fill_bytes(&mut psk);
        (
            Box::new(AlignedPacket([0; 256])),
            session_with_peer(ssk_i, spk_r, psk, server_addr),
            session_with_peer(ssk_r, spk_i, psk, client_addr),
        )
    })
    .bench_local_values(|(buf, sessions_i, sessions_r)| {
        roundtrip_impl(buf, server_addr, client_addr, sessions_i, sessions_r)
    })
}

fn roundtrip_impl(
    mut buf: Box<AlignedPacket>,
    server_addr: SocketAddr,
    client_addr: SocketAddr,
    (mut sessions_i, peer_r, key_i): (Sessions, PeerId, StaticPrivateKey),
    (mut sessions_r, peer_i, key_r): (Sessions, PeerId, StaticPrivateKey),
) {
    let mut msg = black_box(*b"Hello, World!\0\0\0");

    // try wrap the message - get back handshake message to send
    let m = match sessions_i.send_message(peer_r, &mut msg).unwrap() {
        rustyguard_core::SendMessage::Handshake(work) => match finish(&sessions_i, &key_i, *work) {
            Event::Write(message) => message,
            _ => panic!("expected initiation"),
        },
        _ => panic!("expecting handshake"),
    };

    // send handshake to server
    let response_buf = {
        let handshake_buf = &mut buf.0[..m.data().len()];
        handshake_buf.copy_from_slice(m.data());
        match sessions_r.recv_message(client_addr, handshake_buf).unwrap() {
            rustyguard_core::Message::Handshake(work) => match finish(&sessions_r, &key_r, *work) {
                Event::Write(message) => message,
                _ => panic!("expected response"),
            },
            _ => panic!("expecting write"),
        }
    };

    // send the handshake response to the client
    let encryptor = {
        buf.0[..response_buf.data().len()].copy_from_slice(response_buf.data());
        let rustyguard_core::Message::Handshake(work) = sessions_i
            .recv_message(server_addr, &mut buf.0[..response_buf.data().len()])
            .unwrap()
        else {
            panic!("expected DH work")
        };
        match finish(&sessions_i, &key_i, *work) {
            Event::HandshakeComplete(encryptor) => encryptor,
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
            rustyguard_core::Message::Read(peer_idx, data) => {
                assert_eq!(peer_idx, peer_i);
                assert_eq!(data, b"Hello, World!\0\0\0")
            }
            _ => panic!("expecting read"),
        }
    }
}

fn finish(sessions: &Sessions, key: &StaticPrivateKey, mut work: Handshake) -> Event {
    loop {
        let secret = SharedSecret::new(CryptoCore::x25519(key, &work.peer_key()).unwrap()).unwrap();
        match work.complete(sessions, secret).unwrap() {
            Event::Handshake(next) => work = next,
            event => return event,
        }
    }
}
