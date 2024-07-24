use std::{future::poll_fn, net::SocketAddr, task::Poll, time::Duration};

use hashbrown::{hash_map::Entry, HashMap};
use rand::{rngs::OsRng, RngCore};
use rustyguard_crypto::{decrypt_cookie, encrypt_cookie, CookieState, HasMac, Key, Mac};
use rustyguard_types::{Cookie, WgMessage};
use subtle::{Choice, CtOption};
use tokio::{io::ReadBuf, net::UdpSocket, time::Instant};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut cookie_state = CookieState::default();
    cookie_state.generate(&mut OsRng);

    // used to talk to external peers only
    let pub_ep = UdpSocket::bind("0.0.0.0:1234").await.unwrap();
    // used to talk to internal peers only
    let priv_ep = UdpSocket::bind("0.0.0.0:1235").await.unwrap();

    // we should update cookie random state every 2 minutes.
    let mut tick = tokio::time::interval(Duration::from_secs(120));

    let mut packet = Box::new(AlignedPacket([0; 2048]));

    // all peers.
    let mut peers: Vec<InternalPeer> = vec![];

    // receiver_id => (created, peer_idx)
    let mut in_sessions = HashMap::<u32, (Instant, u32)>::new();
    // (in addr, receiver_id) => (created, peer_idx, out addr)
    let mut out_sessions = HashMap::<(SocketAddr, u32), (Instant, u32, SocketAddr)>::new();

    let overloaded = false;

    loop {
        let mut buf = ReadBuf::new(&mut packet.0);
        let (addr, internal) = poll_fn(|cx| {
            if let Poll::Ready(now) = tick.poll_tick(cx) {
                cookie_state.generate(&mut OsRng);

                // primitive garbage collection for old sessions.
                // REKEY_ATTEMPT_TIME = 90s
                // REJECT_AFTER_TIME = 180s
                // After 270s any session should be considered invalid.
                const TOTAL_SESSION_LIFE: Duration = Duration::from_secs(270);
                in_sessions
                    .retain(|_, (t, _)| now.saturating_duration_since(*t) < TOTAL_SESSION_LIFE);
                out_sessions
                    .retain(|_, (t, _, _)| now.saturating_duration_since(*t) < TOTAL_SESSION_LIFE);
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
                let Some(&(_, _, out_socket)) = out_sessions.get(&(addr, header.receiver.get()))
                else {
                    continue;
                };

                pub_ep.send_to(data, out_socket).await.unwrap();
            }
            WgMessage::Data(header) => {
                let Some(&(_, peer_idx)) = in_sessions.get(&header.receiver.get()) else {
                    continue;
                };
                let peer = &mut peers[peer_idx as usize];
                priv_ep.send_to(data, peer.endpoint).await.unwrap();
            }
            // we need to rewrite cookies going outbound
            WgMessage::Cookie(cookie_msg) if internal => {
                let Some(&(_, peer_idx, out_socket)) =
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
                let Some(&(_, peer_idx)) = in_sessions.get(&cookie_msg.receiver.get()) else {
                    continue;
                };
                let peer = &mut peers[peer_idx as usize];
                priv_ep.send_to(data, peer.endpoint).await.unwrap();
            }
            WgMessage::Init(_init) if internal => {
                // whoops, no NAT :(
            }
            WgMessage::Resp(_resp) if !internal => {
                // responding to who? we don't send init messages :think:
            }
            WgMessage::Init(init) => {
                // this is shit. hopefully we don't have that many peers.
                // thankfully mac1 checks are fast.
                let peer = peers.iter().enumerate().fold(
                    CtOption::new(0, Choice::from(0)),
                    |acc, (peer_idx, peer)| {
                        let mac1 = init.compute_mac1(&peer.mac1_key);

                        acc.or_else(|| {
                            CtOption::new(peer_idx as u32, Choice::from((init.mac1 == mac1) as u8))
                        })
                    },
                );

                let Some(peer_idx) = peer.into_option() else {
                    continue;
                };

                let peer = &peers[peer_idx as usize];

                // mac2 was sent, let's check it and replace it.
                if init.mac2 != [0; 16] || overloaded {
                    if init.verify_mac2(&cookie_state.new_cookie(addr)).is_err() {
                        continue;
                    }
                    if let Some(cookie) = &peer.last_sent_cookie {
                        init.mac2 = init.compute_mac2(cookie);
                    }
                }

                match out_sessions.entry((peer.endpoint, init.sender.get())) {
                    // unlucky...
                    // i would like to replace the sender, but unfortunately there's
                    // no way as the response message sent back we cannot forge the
                    // mac1 that we would need to replace.
                    Entry::Occupied(_) => {
                        continue;
                    }
                    Entry::Vacant(v) => {
                        v.insert((Instant::now(), peer_idx, addr));
                    }
                }

                priv_ep.send_to(data, peer.endpoint).await.unwrap();
            }
            WgMessage::Resp(resp) => {
                let Some(&(start, peer_idx, endpoint)) =
                    out_sessions.get(&(addr, resp.receiver.get()))
                else {
                    continue;
                };

                match in_sessions.entry(resp.sender.get()) {
                    // unlucky...
                    // i would like to replace the sender, but unfortunately there's
                    // no way as the response message sent back we cannot forge the
                    // mac1 that we would need to replace.
                    Entry::Occupied(_) => {
                        continue;
                    }
                    Entry::Vacant(v) => {
                        v.insert((start, peer_idx));
                    }
                }

                pub_ep.send_to(data, endpoint).await.unwrap();
            }
        }
    }
}

struct InternalPeer {
    // pk: PublicKey,
    mac1_key: Key,
    cookie_key: Key,
    endpoint: SocketAddr,

    // cookie sent from internal to external
    last_sent_cookie: Option<Cookie>,
    // mac1 sent from external to internal
    last_recv_mac1: Mac,
}

/// 16-byte aligned packet of 2048 bytes.
/// MTU is assumed to be in the range of 1500 or so, so 2048 should be sufficient.
#[repr(align(16))]
struct AlignedPacket([u8; 2048]);
