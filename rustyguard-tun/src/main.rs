use rand::rngs::OsRng;
use rustyguard_tun::{handle_extern, handle_intern, tun, AlignedPacket, TunConfig, Write, H};
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

    let (mut sessions, peer_net) = args.build();

    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        let mut ep_buf = ReadBuf::new(&mut buf.0);
        let mut tun_buf = ReadBuf::new(&mut reply_buf[H..]);
        let write = tokio::select! {
            _ = tick.tick() => {
                while let Some(msg) = sessions.turn(Tai64N::now(), &mut OsRng) {
                    endpoint.send_to(msg.data(), msg.to()).await.unwrap();
                }

                Write::None
            }
            res = endpoint.recv_buf_from(&mut ep_buf) => {
                let addr = res.unwrap().1;

                handle_extern(&mut sessions, &peer_net, addr, ep_buf.filled_mut())
            }
            res = dev.read_buf(&mut tun_buf) => {
                let n = res.unwrap();
                handle_intern(&mut sessions, &peer_net, &mut reply_buf, H + n)
            }
        };

        match write {
            Write::None => {}
            Write::Inbound(buf) => dev.write_all(buf).await.unwrap(),
            Write::Outbound(buf, addr) => {
                endpoint.send_to(buf, addr).await.unwrap();
            }
        }
    }
}
