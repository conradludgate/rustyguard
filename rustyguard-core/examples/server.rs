use std::{
    net::UdpSocket,
    ops::{Deref, DerefMut},
};

use base64ct::{Base64, Encoding};
use clap::Parser;
use packet::{Builder, Packet};
use rand::{rngs::OsRng, Rng};
use rustyguard_core::{Config, Message, PrivateKey, PublicKey, Sessions};
use rustyguard_crypto::StaticPeerConfig;
use tai64::Tai64N;

/// 16-byte aligned packet of 2048 bytes.
/// MTU is assumed to be in the range of 1500 or so, so 2048 should be sufficient.
#[repr(align(16))]
struct AlignedPacket([u8; 2048]);

#[derive(clap::Parser)]
struct Args {
    #[arg(long)]
    peer: Vec<String>,

    #[arg(long, short)]
    port: u16,

    #[arg(long, short)]
    key: Option<String>,
}

fn main() {
    let args = Args::parse();

    let private_key = match args.key {
        Some(key) => {
            let pk = Base64::decode_vec(&key).unwrap();
            let private_key = PrivateKey::from_array(&pk.try_into().unwrap());
            println!(
                "public key: {}",
                Base64::encode_string(&private_key.public_key().as_bytes())
            );
            private_key
        }
        None => {
            let private_key = PrivateKey::from_array(&OsRng.gen());
            let c = private_key.as_bytes();
            println!("private key: {}", Base64::encode_string(c.as_ref()));
            println!(
                "public key: {}",
                Base64::encode_string(&private_key.public_key().as_bytes())
            );
            private_key
        }
    };

    let mut config = Config::new(private_key);
    for peer in args.peer {
        let pk = Base64::decode_vec(&peer).unwrap();
        let peer_pk = PublicKey::from_array(<&[u8; 32]>::try_from(&*pk).unwrap());
        config.insert_peer(StaticPeerConfig::new(peer_pk, None, None));
    }

    let mut sessions = Sessions::new(config, &mut OsRng);

    let endpoint = UdpSocket::bind(("0.0.0.0", args.port)).unwrap();
    println!("addr: {:?}", endpoint.local_addr());

    let mut buf: Box<AlignedPacket> = Box::new(AlignedPacket([0; 2048]));
    let mut reply_buf = vec![0; 2048];

    loop {
        let (n, addr) = endpoint.recv_from(&mut buf.0).unwrap();
        while let Some(msg) = sessions.turn(Tai64N::now(), &mut OsRng) {
            endpoint.send_to(msg.data(), msg.to()).unwrap();
        }

        println!("packet from {addr:?}: {:?}", &buf.0[..n]);
        match sessions.recv_message(addr, &mut buf.0[..n]) {
            Err(err) => println!("error: {err:?}"),
            Ok(Message::Noop) => println!("noop"),
            Ok(Message::HandshakeComplete(_encryptor)) => {}
            Ok(Message::Read(peer, buf)) => {
                if buf.is_empty() {
                    continue;
                }

                let inner_reply_buf = &mut reply_buf[16..];
                let ip = packet::ip::Packet::unchecked(buf);
                match ip {
                    packet::ip::Packet::V4(v4) => {
                        let builder = packet::ip::v4::Builder::with(SliceBuf::new(inner_reply_buf))
                            .unwrap()
                            .destination(v4.source())
                            .unwrap()
                            .source(v4.destination())
                            .unwrap();

                        match v4.protocol() {
                            packet::ip::Protocol::Tcp => todo!(),
                            packet::ip::Protocol::Icmp => {
                                let icmp_builder = builder.icmp().unwrap();

                                let icmp = packet::icmp::Packet::unchecked(v4.payload());
                                if let Ok(e) = icmp.echo() {
                                    if e.is_request() {
                                        let reply = icmp_builder
                                            .echo()
                                            .unwrap()
                                            .reply()
                                            .unwrap()
                                            .sequence(e.sequence())
                                            .unwrap()
                                            .identifier(e.identifier())
                                            .unwrap()
                                            .payload(e.payload())
                                            .unwrap()
                                            .build()
                                            .unwrap();

                                        // pad up to 16
                                        let reply_len = reply.len().next_multiple_of(16);

                                        match sessions
                                            .send_message(peer, &mut inner_reply_buf[..reply_len])
                                            .unwrap()
                                        {
                                            rustyguard_core::SendMessage::Maintenance(_) => todo!(),
                                            rustyguard_core::SendMessage::Data(_, metadata) => {
                                                let buf = &mut reply_buf[..reply_len + 16 + 16];
                                                metadata.frame_in_place(buf);
                                                endpoint.send_to(buf, addr).unwrap();
                                            }
                                        }
                                    } else {
                                        todo!()
                                    }
                                } else {
                                    todo!()
                                }
                            }
                            _ => todo!(),
                        }
                    }
                    packet::ip::Packet::V6(_) => todo!(),
                }
            }
            Ok(Message::Write(buf)) => {
                println!("sending: {buf:?}");
                endpoint.send_to(buf, addr).unwrap();
            }
        }
    }
}

/// A static buffer.
#[derive(Eq, PartialEq, Debug)]
pub struct SliceBuf<'a> {
    inner: &'a mut [u8],

    offset: usize,
    length: usize,
    used: usize,
}

impl<'a> SliceBuf<'a> {
    /// Create a new static buffer wrapping the given slice.
    pub fn new(slice: &mut [u8]) -> SliceBuf<'_> {
        SliceBuf {
            inner: slice,

            offset: 0,
            length: 0,
            used: 0,
        }
    }
}

impl<'a> packet::Buffer for SliceBuf<'a> {
    type Inner = &'a mut [u8];

    fn into_inner(self) -> Self::Inner {
        &mut self.inner[0..self.used]
    }

    fn next(&mut self, size: usize) -> packet::Result<()> {
        if self.inner.len() < self.used + size {
            Err(packet::Error::SmallBuffer)?
        }

        self.offset = self.used;
        self.length = size;
        self.used += size;

        for byte in self.data_mut() {
            *byte = 0;
        }

        Ok(())
    }

    fn more(&mut self, size: usize) -> packet::Result<()> {
        if self.inner.len() < self.used + size {
            Err(packet::Error::SmallBuffer)?
        }

        // self.offset  = self.used;
        self.length += size;
        self.used += size;

        let length = self.length;
        for byte in &mut self.data_mut()[length - size..] {
            *byte = 0;
        }

        Ok(())
    }

    fn clear(&mut self) {
        self.offset = 0;
        self.length = 0;
        self.used = 0;
    }

    fn used(&self) -> usize {
        self.used
    }

    fn offset(&self) -> usize {
        self.offset
    }

    fn length(&self) -> usize {
        self.length
    }

    fn data(&self) -> &[u8] {
        &self.inner[self.offset..self.offset + self.length]
    }

    fn data_mut(&mut self) -> &mut [u8] {
        &mut self.inner[self.offset..self.offset + self.length]
    }
}

impl<'a> AsRef<[u8]> for SliceBuf<'a> {
    fn as_ref(&self) -> &[u8] {
        use packet::Buffer;
        self.data()
    }
}

impl<'a> AsMut<[u8]> for SliceBuf<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        use packet::Buffer;
        self.data_mut()
    }
}

impl<'a> Deref for SliceBuf<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        use packet::Buffer;
        self.data()
    }
}

impl<'a> DerefMut for SliceBuf<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        use packet::Buffer;
        self.data_mut()
    }
}
