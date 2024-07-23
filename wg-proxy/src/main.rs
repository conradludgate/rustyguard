use std::{future::poll_fn, net::SocketAddr, task::Poll, time::Duration};

use hashbrown::HashMap;
use rand::{rngs::OsRng, RngCore};
use rustyguard_crypto::{decrypt_cookie, encrypt_cookie, CookieState, HasMac, Key, Mac, PublicKey};
use rustyguard_types::{Cookie, WgMessage};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use tokio::{io::ReadBuf, net::UdpSocket};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut cookie_state = CookieState::default();
    cookie_state.generate(&mut OsRng);

    let mut pub_ep = UdpSocket::bind("0.0.0.0:1234").await.unwrap();
    let mut priv_ep = UdpSocket::bind("0.0.0.0:1235").await.unwrap();
    let mut tick = tokio::time::interval(Duration::from_secs(120));

    let mut packet = Box::new(AlignedPacket([0; 2048]));

    let mut peers: Vec<InternalPeer> = vec![];
    // receiver_id => peer_idx
    let mut in_sessions = HashMap::<u32, u32>::new();
    // (in addr, receiver_id) => (peer_idx, out addr)
    let mut out_sessions = HashMap::<(SocketAddr, u32), (u32, SocketAddr)>::new();

    // (in addr, sender_id) => (peer_idx, out addr)
    let mut handshakes = HashMap::<(SocketAddr, u32), (u32, SocketAddr)>::new();

    let overloaded = false;

    loop {
        let mut buf = ReadBuf::new(&mut packet.0);
        let (addr, internal) = poll_fn(|cx| {
            if tick.poll_tick(cx).is_ready() {
                cookie_state.generate(&mut OsRng);
            }

            if let Poll::Ready(res) = pub_ep.poll_recv_from(cx, &mut buf) {
                return Poll::Ready((res.unwrap(), false));
            }

            if let Poll::Ready(res) = priv_ep.poll_recv_from(cx, &mut buf) {
                return Poll::Ready((res.unwrap(), true));
            }

            Poll::Pending
        })
        .await;
        let data = buf.initialized_mut();

        let Some(wg) = WgMessage::mut_from(data) else {
            continue;
        };

        match wg {
            WgMessage::Data(header) if internal => {
                let Some(&(_, out_socket)) = out_sessions.get(&(addr, header.receiver.get()))
                else {
                    continue;
                };

                pub_ep.send_to(data, out_socket).await.unwrap();
            }
            WgMessage::Data(header) => {
                let Some(&peer_idx) = in_sessions.get(&header.receiver.get()) else {
                    continue;
                };
                let peer = &mut peers[peer_idx as usize];
                priv_ep.send_to(data, peer.endpoint).await.unwrap();
            }
            // we need to rewrite cookies going outbound
            WgMessage::Cookie(cookie_msg) if internal => {
                let Some(&(peer_idx, out_socket)) =
                    out_sessions.get(&(addr, cookie_msg.receiver.get()))
                else {
                    continue;
                };

                let peer = &mut peers[peer_idx as usize];
                let Ok(cookie) = decrypt_cookie(
                    &mut cookie_msg.cookie,
                    &peer.cookie_key,
                    &cookie_msg.nonce,
                    &peer.last_recv_mac1,
                ) else {
                    continue;
                };

                peer.last_sent_cookie = Some(*cookie);

                // generate a new nonce and encrypt our new cookie.
                OsRng.fill_bytes(&mut cookie_msg.nonce);
                cookie_msg.cookie = encrypt_cookie(
                    cookie_state.new_cookie(out_socket),
                    &peer.cookie_key,
                    &cookie_msg.nonce,
                    &peer.last_recv_mac1,
                );

                pub_ep.send_to(data, out_socket).await.unwrap();
            }
            // we do not rewrite inbound cookie messages
            WgMessage::Cookie(cookie_msg) => {
                let Some(&peer_idx) = in_sessions.get(&cookie_msg.receiver.get()) else {
                    continue;
                };
                let peer = &mut peers[peer_idx as usize];
                priv_ep.send_to(data, peer.endpoint).await.unwrap();
            }
            WgMessage::Init(_init) if internal => {
                // whoops, no NAT :(
            }
            WgMessage::Resp(_resp) => {
                // responding to who? we don't send init messages :think:
            }
            WgMessage::Init(init) => {
                // this is shit. hopefully we don't have that many peers.
                // thankfully mac1 checks are fast.
                let peer = peers.iter().enumerate().fold(
                    CtOption::new(0, Choice::from(0)),
                    |acc, (peer_idx, peer)| {
                        let mac1 = init.compute_mac1(&peer.mac1_key);

                        acc.or_else(|| CtOption::new(peer_idx as u32, init.mac1.ct_eq(&mac1)))
                    },
                );

                let Some(peer_idx) = peer.into_option() else {
                    continue;
                };

                // mac2 was sent, let's check it.
                if (init.mac2 != [0; 16] || overloaded)
                    && init.verify_mac2(&cookie_state.new_cookie(addr)).is_err()
                {
                    continue;
                }

                let peer = &peers[peer_idx as usize];

                // todo: replace the sender
                // as it's not used in the noise handshake ;)
                // hehe
                handshakes.insert((peer.endpoint, init.sender.get()), (peer_idx, addr));

                // mac2 was sent, let's replace it.
                // we checked it above.
                if init.mac2 != [0; 16] || overloaded {
                    if let Some(cookie) = &peer.last_sent_cookie {
                        init.mac2 = init.compute_mac2(cookie);
                    }
                }

                priv_ep.send_to(data, peer.endpoint).await.unwrap();
            }
            WgMessage::Resp(resp) if internal => {}
        }
    }
}

struct InternalPeer {
    pk: PublicKey,
    mac1_key: Key,
    cookie_key: Key,
    endpoint: SocketAddr,

    // cookie sent from external to internal
    last_recv_cookie: Option<Cookie>,
    // cookie sent from internal to external
    last_sent_cookie: Option<Cookie>,
    // mac1 sent from external to internal
    last_recv_mac1: Mac,
    // mac1 sent from internal to external
    last_sent_mac1: Mac,
}

/// 16-byte aligned packet of 2048 bytes.
/// MTU is assumed to be in the range of 1500 or so, so 2048 should be sufficient.
#[repr(align(16))]
struct AlignedPacket([u8; 2048]);
