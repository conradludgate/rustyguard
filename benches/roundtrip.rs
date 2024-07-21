use core::net::SocketAddr;

use chacha20poly1305::Key;
use divan::{black_box, Bencher};
use rand::{thread_rng, RngCore};
use tai64::Tai64N;
use x25519_dalek::{PublicKey, StaticSecret};

use rustyguard::{Config, Peer, PeerId, Sessions};

fn main() {
    divan::main()
}

fn session_with_peer(
    secret_key: StaticSecret,
    peer_public_key: PublicKey,
    preshared_key: Key,
    endpoint: SocketAddr,
) -> (Sessions, PeerId) {
    let peer = Peer::new(peer_public_key, Some(preshared_key), Some(endpoint));
    let mut config = Config::new(secret_key);
    let id = config.insert_peer(peer);
    (Sessions::new(config, Tai64N::now(), &mut thread_rng()), id)
}

#[repr(align(16))]
struct AlignedPacket([u8; 256]);

#[divan::bench(sample_count = 100, sample_size = 100)]
fn roundtrip(b: Bencher) {
    let server_addr: SocketAddr = "10.0.1.1:1234".parse().unwrap();
    let client_addr: SocketAddr = "10.0.2.1:1234".parse().unwrap();

    b.with_inputs(|| {
        let ssk_i = StaticSecret::random_from_rng(thread_rng());
        let ssk_r = StaticSecret::random_from_rng(thread_rng());
        let spk_i = PublicKey::from(&ssk_i);
        let spk_r = PublicKey::from(&ssk_r);
        let mut psk = Key::default();
        thread_rng().fill_bytes(&mut psk);
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
    (mut sessions_i, peer_r): (Sessions, PeerId),
    (mut sessions_r, peer_i): (Sessions, PeerId),
) {
    let mut msg = black_box(*b"Hello, World!\0\0\0");

    // try wrap the message - get back handshake message to send
    let m = match sessions_i.send_message(peer_r, &mut msg).unwrap() {
        rustyguard::SendMessage::Maintenance(m) => m,
        rustyguard::SendMessage::Data(_, _) => panic!("expecting handshake"),
    };

    // send handshake to server
    let response_buf = {
        let handshake_buf = &mut buf.0[..m.data().len()];
        handshake_buf.copy_from_slice(m.data());
        match sessions_r.recv_message(client_addr, handshake_buf).unwrap() {
            rustyguard::Message::Write(buf) => buf,
            _ => panic!("expecting write"),
        }
    };

    // send the handshake response to the client
    let encryptor = {
        match sessions_i.recv_message(server_addr, response_buf).unwrap() {
            rustyguard::Message::HandshakeComplete(peer_idx, encryptor) => {
                assert_eq!(peer_idx, peer_i);
                encryptor
            }
            _ => panic!("expecting noop"),
        }
    };

    // wrap the messasge and encode into buffer
    let data_msg = {
        let metadata = encryptor.encrypt(&mut msg);
        buf.0[..16].copy_from_slice(metadata.header.as_ref());
        buf.0[16..32].copy_from_slice(&msg);
        buf.0[32..48].copy_from_slice(&metadata.tag);
        &mut buf.0[..48]
    };

    // send the buffer to the server
    {
        match sessions_r.recv_message(client_addr, data_msg).unwrap() {
            rustyguard::Message::Read(peer_idx, data) => {
                assert_eq!(peer_idx, peer_i);
                assert_eq!(data, b"Hello, World!\0\0\0")
            }
            _ => panic!("expecting read"),
        }
    }
}
