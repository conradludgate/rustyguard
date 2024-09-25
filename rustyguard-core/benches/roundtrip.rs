use core::net::SocketAddr;

use divan::{black_box, Bencher};
use rand::{thread_rng, RngCore};
use rustyguard_core::{PrivateKey, UnparsedPublicKey};
use rustyguard_crypto::{Key, StaticPeerConfig};
use zerocopy::AsBytes;

use rustyguard_core::{Config, PeerId, Sessions};

fn main() {
    divan::main()
}

fn session_with_peer(
    secret_key: PrivateKey,
    peer_public_key: UnparsedPublicKey,
    preshared_key: Key,
    endpoint: SocketAddr,
) -> (Sessions, PeerId) {
    let peer = StaticPeerConfig::new(peer_public_key, Some(preshared_key), Some(endpoint));
    let mut config = Config::new(secret_key);
    let id = config.insert_peer(peer);
    let sessions = Sessions::new(config, &mut thread_rng());
    (sessions, id)
}

#[repr(align(16))]
struct AlignedPacket([u8; 256]);

fn pk(s: &PrivateKey) -> UnparsedPublicKey {
    UnparsedPublicKey::new(s.compute_public_key().unwrap().as_ref().try_into().unwrap())
}

#[divan::bench(sample_count = 100, sample_size = 100)]
fn roundtrip(b: Bencher) {
    let server_addr: SocketAddr = "10.0.1.1:1234".parse().unwrap();
    let client_addr: SocketAddr = "10.0.2.1:1234".parse().unwrap();

    b.with_inputs(|| {
        let ssk_i = PrivateKey::generate().unwrap();
        let ssk_r = PrivateKey::generate().unwrap();
        let spk_i = pk(&ssk_i);
        let spk_r = pk(&ssk_r);
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
        rustyguard_core::SendMessage::Maintenance(m) => m,
        rustyguard_core::SendMessage::Data(_, _) => panic!("expecting handshake"),
    };

    // send handshake to server
    let response_buf = {
        let handshake_buf = &mut buf.0[..m.data().len()];
        handshake_buf.copy_from_slice(m.data());
        match sessions_r.recv_message(client_addr, handshake_buf).unwrap() {
            rustyguard_core::Message::Write(buf) => buf,
            _ => panic!("expecting write"),
        }
    };

    // send the handshake response to the client
    let encryptor = {
        match sessions_i.recv_message(server_addr, response_buf).unwrap() {
            rustyguard_core::Message::HandshakeComplete(encryptor) => encryptor,
            _ => panic!("expecting noop"),
        }
    };

    // wrap the messasge and encode into buffer
    let data_msg = {
        let metadata = encryptor.encrypt(&sessions_i, &mut msg);
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
