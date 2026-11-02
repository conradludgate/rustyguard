use rand::{rngs::OsRng, TryRngCore};
use rustyguard_core::{Event, Sessions, StaticPrivateKey};
use rustyguard_crypto::{CryptoCore, CryptoPrimatives, SharedSecret};
use rustyguard_tun::{
    handle_extern, handle_intern, tun, AlignedPacket, TunConfig, Write, TUN_BUF_START,
};
use tai64::Tai64N;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::UdpSocket,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = TunConfig::parse();

    let mut buf: Box<AlignedPacket> = Box::new(AlignedPacket([0; 2048]));
    let mut reply_buf = vec![0; 2048];

    let endpoint = UdpSocket::bind(args.interface.host).await.unwrap();

    let mut config = tun::Configuration::default();
    config
        .address(args.interface.addr.addr())
        .netmask(args.interface.addr.netmask())
        .up();
    let mut dev = tun::create_as_async(&config).unwrap();

    let private_key = args.key();
    let (mut sessions, peer_net) = args.build(CryptoCore::x25519_pubkey(&private_key));

    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        let mut ep_buf = ReadBuf::new(&mut buf.0);
        let mut tun_buf = ReadBuf::new(&mut reply_buf[TUN_BUF_START..]);
        let write = tokio::select! {
            _ = tick.tick() => {
                while let Some(msg) = sessions.turn(Tai64N::now(), &mut OsRng.unwrap_err()) {
                    handle_event(msg, &sessions, &private_key, &endpoint).await;
                }

                Write::None
            }
            res = endpoint.recv_buf_from(&mut ep_buf) => {
                let addr = res.unwrap().1;

                handle_extern(&mut sessions, &peer_net, addr, ep_buf.filled_mut())
            }
            res = dev.read_buf(&mut tun_buf) => {
                let n = res.unwrap();
                handle_intern(&mut sessions, &peer_net, &mut reply_buf, TUN_BUF_START + n)
            }
        };

        match write {
            Write::Handshake(work) => {
                handle_event(Event::Handshake(*work), &sessions, &private_key, &endpoint).await
            }
            Write::None => {}
            Write::Inbound(buf) => dev.write_all(buf).await.unwrap(),
            Write::Outbound(buf, addr) => {
                endpoint.send_to(buf, addr).await.unwrap();
            }
        }
    }
}

// The application owns the static key and chooses how each DH request is served.
// An HSM application would move the owned work into its device future,
// then return the completed agreement to its event loop.
async fn handle_event(
    mut event: Event,
    sessions: &Sessions,
    key: &StaticPrivateKey,
    endpoint: &UdpSocket,
) {
    loop {
        match event {
            Event::Handshake(work) => {
                let next: Result<Event, rustyguard_core::Error> = (|| {
                    let secret = SharedSecret::new(CryptoCore::x25519(key, &work.peer_key())?)?;
                    work.complete(sessions, secret)
                })();
                match next {
                    Ok(next) => event = next,
                    Err(err) => {
                        eprintln!("handshake error: {err:?}");
                        return;
                    }
                }
            }
            Event::Write(message) => {
                endpoint
                    .send_to(message.data(), message.to())
                    .await
                    .unwrap();
                return;
            }
            Event::HandshakeComplete(_encrypter) => {
                // TODO(conrad): resend queued message on the completed transport.
                return;
            }
        }
    }
}
