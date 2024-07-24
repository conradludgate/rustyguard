use std::{future::poll_fn, net::SocketAddr, sync::RwLock, task::Poll, time::Duration};

use dashmap::{DashMap, Entry};
use rand::{rngs::OsRng, RngCore};
use rustyguard_crypto::{decrypt_cookie, encrypt_cookie, CookieState, HasMac, Key, Mac};
use rustyguard_types::{Cookie, WgMessage};
use sharded_slab::{Clear, Pool};
use slotmap::{DefaultKey, Key as _, KeyData, SlotMap};
use subtle::{Choice, CtOption};
use tokio::{io::ReadBuf, net::UdpSocket, sync::Mutex, time::Instant};

type PeerId = DefaultKey;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cookie_state = RwLock::new(CookieState::default());
    cookie_state.write().unwrap().generate(&mut OsRng);

    // used to talk to external peers only
    let pub_ep = UdpSocket::bind("0.0.0.0:1234").await.unwrap();
    // used to talk to internal peers only
    let priv_ep = UdpSocket::bind("0.0.0.0:1235").await.unwrap();

    // we should update cookie random state every 2 minutes.
    let mut tick = tokio::time::interval(Duration::from_secs(120));

    let pool = Pool::<Box<AlignedPacket>>::new();

    // all peers.
    let peers: Mutex<SlotMap<PeerId, InternalPeer>> = Mutex::new(SlotMap::new());

    // receiver_id => (created, peer_idx)
    let in_sessions = DashMap::<u32, (Instant, PeerId)>::new();
    // (in addr, receiver_id) => (created, peer_idx, out addr)
    let out_sessions = DashMap::<(SocketAddr, u32), (Instant, PeerId, SocketAddr)>::new();

    let overloaded = false;

    loop {
        let mut packet = pool.create().unwrap();
        let mut buf = ReadBuf::new(&mut packet.0);
        let (addr, internal) = poll_fn(|cx| {
            if let Poll::Ready(now) = tick.poll_tick(cx) {
                cookie_state.write().unwrap().generate(&mut OsRng);

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
                let Some(session) = out_sessions.get(&(addr, header.receiver.get())) else {
                    continue;
                };
                let (_, _, out_socket) = *session;

                pub_ep.send_to(data, out_socket).await.unwrap();
            }
            WgMessage::Data(header) => {
                let Some(session) = in_sessions.get(&header.receiver.get()) else {
                    continue;
                };
                let (_, peer_idx) = *session;

                let peer = &mut peers.lock().await[peer_idx];
                priv_ep.send_to(data, peer.endpoint).await.unwrap();
            }
            // we need to rewrite cookies going outbound
            WgMessage::Cookie(cookie_msg) if internal => {
                let Some(session) = out_sessions.get(&(addr, cookie_msg.receiver.get())) else {
                    continue;
                };
                let (_, peer_idx, out_socket) = *session;

                let peer = &mut peers.lock().await[peer_idx];
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
                    cookie_state.read().unwrap().new_cookie(out_socket),
                    &peer.cookie_key,
                    &cookie_msg.nonce,
                    &peer.last_recv_mac1,
                );

                pub_ep.send_to(data, out_socket).await.unwrap();
            }
            // we do not rewrite inbound cookie messages
            WgMessage::Cookie(cookie_msg) => {
                let Some(session) = in_sessions.get(&cookie_msg.receiver.get()) else {
                    continue;
                };
                let (_, peer_idx) = *session;
                let peer = &mut peers.lock().await[peer_idx];
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
                let peer = peers.lock().await.iter().fold(
                    CtOption::new(0, Choice::from(0)),
                    |acc, (peer_idx, peer)| {
                        let mac1 = init.compute_mac1(&peer.mac1_key);

                        acc.or_else(|| {
                            CtOption::new(
                                peer_idx.data().as_ffi(),
                                Choice::from((init.mac1 == mac1) as u8),
                            )
                        })
                    },
                );

                let Some(peer_idx) = peer.into_option() else {
                    continue;
                };
                let peer_idx = PeerId::from(KeyData::from_ffi(peer_idx));
                let peer = &peers.lock().await[peer_idx];

                // mac2 was sent, let's check it and replace it.
                if init.mac2 != [0; 16] || overloaded {
                    let cookie = cookie_state.read().unwrap().new_cookie(addr);
                    if init.verify_mac2(&cookie).is_err() {
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
                let Some(session) = out_sessions.get(&(addr, resp.receiver.get())) else {
                    continue;
                };
                let (start, peer_idx, endpoint) = *session;

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

impl Default for AlignedPacket {
    fn default() -> Self {
        Self([0; 2048])
    }
}

impl Clear for AlignedPacket {
    fn clear(&mut self) {
        // nothing to clear.
    }
}
