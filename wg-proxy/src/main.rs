use std::{
    future::poll_fn,
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock},
    task::Poll,
    time::Duration,
};

use dashmap::{DashMap, Entry};
use rand::{rngs::OsRng, TryRngCore};
use rustyguard_crypto::{decrypt_cookie, encrypt_cookie, CookieState, HasMac, Key, Mac};
use rustyguard_types::{Cookie, WgMessage};
use slotmap::{DefaultKey, Key as _, KeyData, SlotMap};
use subtle::{Choice, CtOption};
use tokio::{io::ReadBuf, net::UdpSocket, time::Instant};

type PeerId = DefaultKey;

#[tokio::main]
async fn main() {
    let mut rng = OsRng.unwrap_err();
    let cookie_state = RwLock::new(CookieState::new(&mut rng));
    cookie_state.write().unwrap().generate(&mut rng);

    // used to talk to external peers only
    let pub_ep = UdpSocket::bind("0.0.0.0:1234").await.unwrap();
    // used to talk to internal peers only
    let priv_ep = UdpSocket::bind("0.0.0.0:1235").await.unwrap();

    // all peers.
    let peers: Mutex<SlotMap<PeerId, InternalPeer>> = Mutex::new(SlotMap::new());

    // receiver_id => (created, peer_idx)
    let in_sessions = DashMap::<u32, (Instant, PeerId)>::new();
    // (in addr, receiver_id) => (created, peer_idx, out addr)
    let out_sessions = DashMap::<(SocketAddr, u32), (Instant, PeerId, SocketAddr)>::new();

    let state = Arc::new(State {
        pub_ep,
        priv_ep,
        cookie_state,
        peers,
        in_sessions,
        out_sessions,
    });

    // primitive garbage collection for old sessions.
    let state2 = Arc::clone(&state);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            let now = tick.tick().await;

            // REKEY_ATTEMPT_TIME = 90s
            // REJECT_AFTER_TIME = 180s
            // After 270s any session should be considered invalid.
            const TOTAL_SESSION_LIFE: Duration = Duration::from_secs(270);

            state2
                .in_sessions
                .retain(|_, (t, _)| now.saturating_duration_since(*t) < TOTAL_SESSION_LIFE);
            state2
                .out_sessions
                .retain(|_, (t, _, _)| now.saturating_duration_since(*t) < TOTAL_SESSION_LIFE);
        }
    });

    // we should update cookie random state every 2 minutes.
    let state2 = Arc::clone(&state);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(120));
        loop {
            tick.tick().await;
            state2.cookie_state.write().unwrap().generate(&mut rng);
        }
    });

    tokio::spawn(async move {
        loop {
            let mut packet = Box::new(AlignedPacket::default());
            let mut buf = ReadBuf::new(&mut packet.0);
            let (addr, internal) = poll_fn(|cx| {
                if let Poll::Ready(res) = state.pub_ep.poll_recv_from(cx, &mut buf) {
                    return Poll::Ready((res.unwrap(), false));
                }

                if let Poll::Ready(res) = state.priv_ep.poll_recv_from(cx, &mut buf) {
                    return Poll::Ready((res.unwrap(), true));
                }

                Poll::Pending
            })
            .await;

            let filled = buf.initialized().len();

            let state2 = Arc::clone(&state);
            tokio::spawn(async move {
                let mut packet = packet;
                let data = &mut packet.0[..filled];
                state2.handle_packet(addr, data, internal).await;
            });
        }
    })
    .await
    .unwrap();
}

struct State {
    pub_ep: UdpSocket,
    priv_ep: UdpSocket,

    cookie_state: RwLock<CookieState>,
    peers: Mutex<SlotMap<PeerId, InternalPeer>>,

    // receiver_id => (created, peer_idx)
    in_sessions: DashMap<u32, (Instant, PeerId)>,
    // (in addr, receiver_id) => (created, peer_idx, out addr)
    out_sessions: DashMap<(SocketAddr, u32), (Instant, PeerId, SocketAddr)>,
}

impl State {
    async fn handle_packet(&self, addr: SocketAddr, data: &mut [u8], internal: bool) {
        let Self {
            pub_ep,
            priv_ep,
            cookie_state,
            peers,
            in_sessions,
            out_sessions,
            ..
        } = self;

        let Some(wg) = WgMessage::mut_from(data) else {
            return;
        };

        let overloaded = false;

        match wg {
            WgMessage::Data(header) if internal => {
                let Some(session) = out_sessions.get(&(addr, header.receiver.get())) else {
                    return;
                };
                let (_, _, out_socket) = *session;

                pub_ep.send_to(data, out_socket).await.unwrap();
            }
            WgMessage::Data(header) => {
                let Some(session) = in_sessions.get(&header.receiver.get()) else {
                    return;
                };
                let (_, peer_idx) = *session;

                let endpoint = peers.lock().unwrap()[peer_idx].endpoint;
                priv_ep.send_to(data, endpoint).await.unwrap();
            }
            // we need to rewrite cookies going outbound
            WgMessage::Cookie(cookie_msg) if internal => {
                let Some(session) = out_sessions.get(&(addr, cookie_msg.receiver.get())) else {
                    return;
                };
                let (_, peer_idx, out_socket) = *session;

                let last_recv_mac1;
                let cookie_key;
                {
                    let mut peers = peers.lock().unwrap();
                    let peer = &mut peers[peer_idx];
                    let Ok(cookie) = decrypt_cookie(
                        &mut cookie_msg.cookie,
                        &peer.cookie_key,
                        &cookie_msg.nonce,
                        &peer.last_recv_mac1,
                    ) else {
                        return;
                    };
                    peer.last_sent_cookie = Some(*cookie);
                    cookie_key = peer.cookie_key;
                    last_recv_mac1 = peer.last_recv_mac1;
                }

                // generate a new nonce and encrypt our new cookie.
                OsRng.try_fill_bytes(&mut cookie_msg.nonce).unwrap();
                cookie_msg.cookie = encrypt_cookie(
                    cookie_state.read().unwrap().new_cookie(out_socket),
                    &cookie_key,
                    &cookie_msg.nonce,
                    &last_recv_mac1,
                );

                pub_ep.send_to(data, out_socket).await.unwrap();
            }
            // we do not rewrite inbound cookie messages
            WgMessage::Cookie(cookie_msg) => {
                let Some(session) = in_sessions.get(&cookie_msg.receiver.get()) else {
                    return;
                };
                let (_, peer_idx) = *session;
                let endpoint = peers.lock().unwrap()[peer_idx].endpoint;
                priv_ep.send_to(data, endpoint).await.unwrap();
            }
            WgMessage::Init(_init) if internal => {
                // whoops, no NAT :(
            }
            WgMessage::Resp(_resp) if !internal => {
                // responding to who? we don't send init messages :think:
            }
            WgMessage::Init(init) => {
                let peer_idx;
                let last_sent_cookie;
                let endpoint;
                {
                    let peers = peers.lock().unwrap();
                    // this is shit. hopefully we don't have that many peers.
                    // thankfully mac1 checks are fast.
                    let peer = peers.iter().fold(
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

                    let Some(peer_idx2) = peer.into_option() else {
                        return;
                    };
                    peer_idx = PeerId::from(KeyData::from_ffi(peer_idx2));
                    let peer = &peers[peer_idx];
                    last_sent_cookie = peer.last_sent_cookie;
                    endpoint = peer.endpoint;
                }

                // mac2 was sent, let's check it and replace it.
                if init.mac2 != [0; 16] || overloaded {
                    let cookie = cookie_state.read().unwrap().new_cookie(addr);
                    if init.verify_mac2(&cookie).is_err() {
                        return;
                    }
                    if let Some(cookie) = &last_sent_cookie {
                        init.mac2 = init.compute_mac2(cookie);
                    }
                }

                match out_sessions.entry((endpoint, init.sender.get())) {
                    // unlucky...
                    // i would like to replace the sender, but unfortunately there's
                    // no way as the response message sent back we cannot forge the
                    // mac1 that we would need to replace.
                    Entry::Occupied(_) => {
                        return;
                    }
                    Entry::Vacant(v) => {
                        v.insert((Instant::now(), peer_idx, addr));
                    }
                }

                priv_ep.send_to(data, endpoint).await.unwrap();
            }
            WgMessage::Resp(resp) => {
                let Some(session) = out_sessions.get(&(addr, resp.receiver.get())) else {
                    return;
                };
                let (start, peer_idx, endpoint) = *session;

                match in_sessions.entry(resp.sender.get()) {
                    // unlucky...
                    // i would like to replace the sender, but unfortunately there's
                    // no way as the response message sent back we cannot forge the
                    // mac1 that we would need to replace.
                    Entry::Occupied(_) => {
                        return;
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
