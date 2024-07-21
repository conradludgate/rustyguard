use core::{net::SocketAddr, ops::ControlFlow};

use chacha20poly1305::Key;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::{byteorder::little_endian, AsBytes, FromBytes, FromZeroes};

use crate::{
    crypto::{
        Cookie, EncryptedCookie, EncryptedEmpty, EncryptedPublicKey, EncryptedTimestamp,
        HandshakeState, Mac,
    },
    Config, Error, Peer, Sessions,
};

impl AsRef<[u8]> for DataHeader {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

pub const MSG_FIRST: u32 = 1;
pub const MSG_SECOND: u32 = 2;
pub const MSG_DATA: u32 = 4;
pub const MSG_COOKIE: u32 = 3;

#[derive(Clone, Copy, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
pub(crate) struct HandshakeInit {
    pub(crate) _type: little_endian::U32,
    pub(crate) sender: little_endian::U32,
    pub(crate) ephemeral_key: [u8; 32],
    pub(crate) static_key: EncryptedPublicKey,
    pub(crate) timestamp: EncryptedTimestamp,
    pub(crate) mac1: Mac,
    pub(crate) mac2: Mac,
}

#[derive(Clone, Copy)]
pub(crate) struct HandshakeInitData {
    pub(crate) sender: u32,
    pub(crate) epk_i: PublicKey,
    pub(crate) spk_i: PublicKey,
    pub(crate) timestamp: [u8; 12],
}

#[derive(Clone, Copy, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
pub(crate) struct HandshakeResp {
    pub(crate) _type: little_endian::U32,
    pub(crate) sender: little_endian::U32,
    pub(crate) receiver: little_endian::U32,
    pub(crate) ephemeral_key: [u8; 32],
    pub(crate) empty: EncryptedEmpty,
    pub(crate) mac1: Mac,
    pub(crate) mac2: Mac,
}

#[derive(Clone, Copy, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
pub(crate) struct CookieMessage {
    pub(crate) _type: little_endian::U32,
    pub(crate) receiver: little_endian::U32,
    pub(crate) nonce: [u8; 24],
    pub(crate) cookie: EncryptedCookie,
}

#[derive(Clone, Copy, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(8))]
pub struct DataHeader {
    pub(crate) _type: little_endian::U32,
    pub(crate) receiver: little_endian::U32,
    pub(crate) counter: little_endian::U64,
}

/// Both handshake messages are protected via MACs which can quickly be used
/// to rule out invalid messages.
///
/// The first MAC verifies that the message is even valid - to not waste time.
/// The second MAC is only checked if the server is overloaded. If the server is
/// overloaded and second MAC is invalid, a CookieReply is sent to the client,
/// which contains an encrypted key that can be used to re-sign the handshake later.
pub(crate) trait HasMac: FromBytes + AsBytes + Sized {
    fn verify<'m>(
        msg: &'m mut [u8],
        state: &mut Sessions,
        socket: SocketAddr,
    ) -> Result<ControlFlow<CookieMessage, &'m mut Self>, Error> {
        let this: &'m mut Self = Self::mut_from(msg).ok_or(Error::InvalidMessage)?;

        // verify the mac1. this should be very fast.
        // takes 450ns on my M2 Max.
        // Thus, can handle ~2 million handshakes per second.
        // This is currently single threaded.
        // TODO(conrad): need to make the rejection multi-threaded.
        this.verify_mac1(&state.config)?;

        if state.overloaded() {
            // Will be roughly twice as slow as verify_mac1. 750ns on my M2 Max.
            // If the server is overloaded, this is good for rejecting DDoS attacks
            // as it requires a round trip from the sender.
            if let Err(cookie) = this.verify_mac2(state, socket) {
                // Generating a random nonce and encrypting the cookie takes 1.3us
                // on my M2 Max. Total time to verify the handshake msg is 2.5us.
                // This brings us to 400k handshakes processed per second.
                // As I said above, this should be parallisable with an rng per thread.
                let mut nonce = [0u8; 24];
                state.rng.fill_bytes(&mut nonce);
                let cookie = EncryptedCookie::encrypt_cookie(
                    cookie,
                    &state.config.cookie_key,
                    &nonce,
                    this.get_mac1(),
                );

                let msg = CookieMessage {
                    _type: little_endian::U32::new(MSG_COOKIE),
                    receiver: this.sender(),
                    nonce,
                    cookie,
                };
                return Ok(ControlFlow::Break(msg));
            }
        }

        Ok(ControlFlow::Continue(this))
    }

    fn verify_mac1(&self, config: &Config) -> Result<(), Error> {
        use subtle::ConstantTimeEq;
        let actual_mac1 = self.compute_mac1(&config.mac1_key);
        if actual_mac1.ct_ne(self.get_mac1()).into() {
            unsafe_log!("invalid mac1");
            Err(Error::Rejected)
        } else {
            unsafe_log!("valid mac1");
            Ok(())
        }
    }

    fn verify_mac2(&self, state: &Sessions, socket: SocketAddr) -> Result<(), Cookie> {
        use subtle::ConstantTimeEq;
        let cookie = state.cookie(socket);
        let actual_mac2 = self.compute_mac2(&cookie);
        if actual_mac2.ct_ne(self.get_mac2()).into() {
            unsafe_log!("invalid mac2");
            Err(cookie)
        } else {
            unsafe_log!("valid mac2");
            Ok(())
        }
    }

    fn compute_mac1(&self, mac1_key: &Key) -> Mac;
    fn compute_mac2(&self, cookie: &Cookie) -> Mac;
    fn get_mac1(&self) -> &Mac;
    fn get_mac2(&self) -> &Mac;
    fn sender(&self) -> little_endian::U32;
}

macro_rules! mac_protected {
    ($i:ident, $t:ident) => {
        impl HasMac for $i {
            fn sender(&self) -> little_endian::U32 {
                self.sender
            }

            fn compute_mac1(&self, mac1_key: &chacha20poly1305::Key) -> Mac {
                let offset = core::mem::offset_of!($i, mac1);
                let bytes = self.as_bytes();
                crate::crypto::mac(mac1_key, &bytes[..offset])
            }

            fn compute_mac2(&self, cookie: &Cookie) -> Mac {
                let offset = core::mem::offset_of!($i, mac2);
                let bytes = self.as_bytes();
                crate::crypto::mac(&cookie.0, &bytes[..offset])
            }

            fn get_mac1(&self) -> &Mac {
                &self.mac1
            }

            fn get_mac2(&self) -> &Mac {
                &self.mac2
            }
        }
    };
}

mac_protected!(HandshakeInit, MSG_FIRST);
mac_protected!(HandshakeResp, MSG_SECOND);

// ---- Noise IKpsk2 ---- //
// Wireguard makes use of a slightly modified Noise IKpsk2 handshake.
// Read the noise specification: https://noiseprotocol.org/noise.html
//
// The IKpsk2 pattern is as follows:
// <- s
// -> e, es, s, ss
// <- e, ee, se, psk
//
// The initiator is expected to know the responder's static public key prior to the handshake.
// The initiator sends an ephemeral public key and their encrypted static public key.
// The responder sends an ephemeral public key.

impl HandshakeInit {
    pub(crate) fn encrypt_for(
        ssk_i: &StaticSecret,
        spk_i: &PublicKey,
        peer: &mut Peer,
        sender: u32,
    ) -> Self {
        let ph = &mut peer.handshake;
        let hs = &mut ph.state;

        // IKpsk2:
        // <- s
        // -> e, es, s, ss

        // <- s:
        let epk_i = PublicKey::from(&ph.esk_i);
        hs.mix_hash(peer.key.as_bytes());

        // -> e: ephemeral keypair generated by caller
        // wireguard goes off-spec here with mix-chain.
        hs.mix_chain(epk_i.as_bytes());
        hs.mix_hash(epk_i.as_bytes());

        // -> es:
        let k = hs.mix_key_dh(&ph.esk_i, &peer.key);

        // -> s:
        let static_key = EncryptedPublicKey::encrypt_and_hash(spk_i.to_bytes(), hs, &k);

        // -> ss:
        let k = hs.mix_key_dh(ssk_i, &peer.key);

        // payload:
        let timestamp = EncryptedTimestamp::encrypt_and_hash(ph.sent.to_bytes(), hs, &k);

        // build the message and protect with the MACs
        let mut msg = Self {
            _type: little_endian::U32::new(MSG_FIRST),
            sender: little_endian::U32::new(sender),
            ephemeral_key: epk_i.to_bytes(),
            static_key,
            timestamp,
            mac1: [0; 16],
            mac2: [0; 16],
        };
        msg.mac1 = msg.compute_mac1(&peer.mac1_key);
        peer.last_sent_mac1 = msg.mac1;
        if let Some(cookie) = peer.cookie.as_ref() {
            msg.mac2 = msg.compute_mac2(cookie);
        }

        msg
    }

    pub(crate) fn decrypt(
        &mut self,
        hs: &mut HandshakeState,
        config: &Config,
    ) -> Result<HandshakeInitData, Error> {
        // IKpsk2:
        // <- s
        // -> e, es, s, ss

        // <- s:
        hs.mix_hash(config.public_key.as_bytes());

        // -> e:
        // wireguard goes off-spec here with mix-chain.
        hs.mix_chain(&self.ephemeral_key);
        hs.mix_hash(&self.ephemeral_key);

        // -> es:
        let epk_i = PublicKey::from(self.ephemeral_key);
        let k = hs.mix_key_dh(&config.private_key, &epk_i);

        unsafe_log!("decrypting static key");
        // -> s:
        let spk_i = self.static_key.decrypt_and_hash(hs, &k)?;
        let spk_i = PublicKey::from(*spk_i);
        unsafe_log!("decrypted public key {spk_i:?}");

        // -> ss:
        let k = hs.mix_key_dh(&config.private_key, &spk_i);

        unsafe_log!("decrypting payload");
        // payload:
        let timestamp = *self.timestamp.decrypt_and_hash(hs, &k)?;

        Ok(HandshakeInitData {
            sender: self.sender.get(),
            epk_i,
            spk_i,
            timestamp,
        })
    }
}

impl HandshakeResp {
    pub(crate) fn encrypt_for(
        hs: &mut HandshakeState,
        data: &HandshakeInitData,
        esk_r: &StaticSecret,
        peer: &mut Peer,
        sender: u32,
    ) -> Self {
        // IKpsk2:
        // <- e, ee, se, psk

        // <- e: ephemeral keypair generated by caller
        // wireguard goes off-spec here with mix-chain.
        let epk_r = PublicKey::from(esk_r);
        hs.mix_chain(epk_r.as_bytes());
        hs.mix_hash(epk_r.as_bytes());

        // <- ee
        hs.mix_dh(esk_r, &data.epk_i);

        // <- se
        hs.mix_dh(esk_r, &data.spk_i);

        // <- psk
        let k = hs.mix_key_and_hash(&peer.preshared_key);

        // payload:
        let empty = EncryptedEmpty::encrypt_and_hash([], hs, &k);

        // build the message and protect with the MACs
        let mut msg = HandshakeResp {
            _type: little_endian::U32::new(MSG_SECOND),
            sender: little_endian::U32::new(sender),
            receiver: little_endian::U32::new(data.sender),
            ephemeral_key: epk_r.to_bytes(),
            empty,
            mac1: [0; 16],
            mac2: [0; 16],
        };
        msg.mac1 = msg.compute_mac1(&peer.mac1_key);
        peer.last_sent_mac1 = msg.mac1;
        if let Some(cookie) = peer.cookie.as_ref() {
            msg.mac2 = msg.compute_mac2(cookie);
        }

        msg
    }

    pub(crate) fn decrypt(
        &mut self,
        peer: &mut Peer,
        private_key: &StaticSecret,
    ) -> Result<(), Error> {
        // IKpsk2:
        // <- e, ee, se, psk

        let hs = &mut peer.handshake.state;

        // <- e:
        // wireguard goes off-spec here with mix-chain.
        let epk_r = PublicKey::from(self.ephemeral_key);
        hs.mix_chain(epk_r.as_bytes());
        hs.mix_hash(epk_r.as_bytes());

        // <- ee:
        hs.mix_dh(&peer.handshake.esk_i, &epk_r);

        // <- se:
        hs.mix_dh(private_key, &epk_r);

        // <- psk:
        let k = hs.mix_key_and_hash(&peer.preshared_key);

        unsafe_log!("decrypting payload");
        // payload:
        self.empty.decrypt_and_hash(hs, &k)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CookieMessage, DataHeader, HandshakeInit, HandshakeResp};

    #[test]
    fn test_size_align() {
        assert_eq!(core::mem::size_of::<HandshakeInit>(), 148);
        assert_eq!(core::mem::align_of::<HandshakeInit>(), 4);

        assert_eq!(core::mem::size_of::<HandshakeResp>(), 92);
        assert_eq!(core::mem::align_of::<HandshakeResp>(), 4);

        assert_eq!(core::mem::size_of::<CookieMessage>(), 64);
        assert_eq!(core::mem::align_of::<CookieMessage>(), 4);

        assert_eq!(core::mem::size_of::<DataHeader>(), 16);
        assert_eq!(core::mem::align_of::<DataHeader>(), 8);
    }
}
