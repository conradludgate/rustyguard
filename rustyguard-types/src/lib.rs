#![no_std]

use zerocopy::{byteorder::little_endian, transmute, FromBytes, Immutable, IntoBytes, KnownLayout};

pub type Mac = [u8; 16];

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(transparent)]
pub struct Cookie(pub Mac);

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(transparent)]
pub struct Tag(pub [u8; 16]);

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct EncryptedEmpty {
    pub msg: [u8; 0],
    pub tag: Tag,
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct EncryptedTimestamp {
    pub msg: [u8; 12],
    pub tag: Tag,
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct EncryptedPublicKey {
    pub msg: [u8; 32],
    pub tag: Tag,
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct EncryptedCookie {
    pub msg: Cookie,
    pub tag: Tag,
}

/// The type of [`HandshakeInit`]
pub const MSG_FIRST: u32 = 1;
/// The type of [`HandshakeResp`]
pub const MSG_SECOND: u32 = 2;
/// The type of [`DataHeader`]
pub const MSG_DATA: u32 = 4;
/// The type of [`CookieMessage`]
pub const MSG_COOKIE: u32 = 3;

#[repr(u32)]
pub enum WgMessage<'a> {
    Init(&'a mut HandshakeInit) = MSG_FIRST,
    Resp(&'a mut HandshakeResp) = MSG_SECOND,
    Cookie(&'a mut CookieMessage) = MSG_COOKIE,
    Data(&'a mut DataHeader) = MSG_DATA,
}

impl<'a> WgMessage<'a> {
    pub fn mut_from(b: &'a mut [u8]) -> Option<Self> {
        // Every message in wireguard starts with a 1 byte message tag and 3 bytes empty.
        // This happens to be easy to read as a little-endian u32.
        let (msg_type, _) = little_endian::U32::ref_from_prefix(b).ok()?;
        match msg_type.get() {
            MSG_FIRST => Some(WgMessage::Init(FromBytes::mut_from_bytes(b).ok()?)),
            MSG_SECOND => Some(WgMessage::Resp(FromBytes::mut_from_bytes(b).ok()?)),
            MSG_COOKIE => Some(WgMessage::Cookie(FromBytes::mut_from_bytes(b).ok()?)),
            MSG_DATA => Some(WgMessage::Data(FromBytes::mut_from_bytes(b).ok()?)),
            _ => None,
        }
    }
}

/// The initiation for a wireguard session handshake.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, align(4))]
pub struct HandshakeInit {
    /// Must always be [`MSG_FIRST`]
    pub _type: little_endian::U32,
    /// A randomly generated ID.
    /// Any incoming messages with this value as the _`receiver`_
    /// will be associated with this session.
    pub sender: little_endian::U32,
    /// Randomly generated x25519 public key.
    pub ephemeral_key: [u8; 32],
    /// The initiator's static public key, encrypted as part of the
    /// Noise IKpsk2 handshake.
    pub static_key: EncryptedPublicKey,
    /// The current timestamp in Tai64N form.
    /// Receivers of this message should reject this handshake
    /// if the timestamp is not the most recent for this peer.
    pub timestamp: EncryptedTimestamp,
    /// All handshake messages come with a fast check
    /// message authentication code that does not require any
    /// expensive diffie-hellman exchanges.
    pub mac1: Mac,
    /// Like the `mac1`, this is a simple message authentication code,
    /// although it keyed using a "cookie" value that is unique per
    /// endpoint IP+Port and changes every 2 minutes.
    /// This is used for DDoS mitigation and requires a round-trip
    /// from the client, acting as a way to validate the IP address.
    pub mac2: Mac,
}

/// The response for a wireguard session handshake.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, align(4))]
pub struct HandshakeResp {
    /// Must always be [`MSG_SECOND`]
    pub _type: little_endian::U32,
    /// A randomly generated ID.
    /// Any incoming messages with this value as the _`receiver`_
    /// will be associated with this session.
    pub sender: little_endian::U32,
    /// Must be set to the same as [`HandshakeInit::sender`]
    pub receiver: little_endian::U32,
    /// Randomly generated x25519 public key.
    pub ephemeral_key: [u8; 32],
    /// Just an encryption tag to test that the handshake worked
    pub empty: EncryptedEmpty,
    /// All handshake messages come with a fast check
    /// message authentication code that does not require any
    /// expensive diffie-hellman exchanges.
    pub mac1: Mac,
    /// Like the `mac1`, this is a simple message authentication code,
    /// although it keyed using a "cookie" value that is unique per
    /// endpoint IP+Port and changes every 2 minutes.
    /// This is used for DDoS mitigation and requires a round-trip
    /// from the client, acting as a way to validate the IP address.
    pub mac2: Mac,
}

/// A cookie message.
///
/// WireGuard will send cookies overloaded, as a way to mitigate
/// certain DDoS attacks.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, align(4))]
pub struct CookieMessage {
    /// Must always be [`MSG_COOKIE`]
    pub _type: little_endian::U32,
    /// Must be set to the same as the received
    /// [`HandshakeInit::sender`] or [`HandshakeResp::sender`].
    pub receiver: little_endian::U32,
    /// Randomly generated nonce.
    pub nonce: [u8; 24],
    /// Encrypted cookie value.
    pub cookie: EncryptedCookie,
}

/// A WireGuard transport data message header.
///
/// A transport data message will consist of the following layout
///
/// ```ignore,rust
/// #[repr(C)]
/// struct DataMessage {
///     header: DataHeader,
///     payload: [u8; n],
///     tag: Tag
/// }
/// ```
///
/// Padding normally rounds the payload length up to a multiple of 16, but
/// WireGuard caps it at the interface MTU, which may not be a multiple of 16.
///
/// Unfortunately, this is impossible to express in the Rust type system
/// with [`zerocopy`], thus we split off the header from the other payload+tag.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C, align(8))]
pub struct DataHeader {
    /// Must always be [`MSG_DATA`]
    pub _type: little_endian::U32,
    /// Must be set to the same as the received
    /// [`HandshakeInit::sender`] or [`HandshakeResp::sender`].
    pub receiver: little_endian::U32,
    /// The nonce-counter for the encrypted payload.
    /// Receivers of this counter should check it for replay-attacks
    /// as well as filtering out counters that are too old.
    pub counter: little_endian::U64,
}

impl DataHeader {
    #[inline(always)]
    pub fn message_mut_from(msg: &mut [u8]) -> Option<(Self, &mut [u8])> {
        #[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
        #[repr(C, align(16))]
        struct DataSegment([u8; 16]);

        let (header, payload_and_tag) = DataSegment::mut_from_prefix(msg).ok()?;
        if payload_and_tag.len() < core::mem::size_of::<Tag>() {
            return None;
        }
        let header: Self = transmute!(*header);
        Some((header, payload_and_tag))
    }
}

#[cfg(test)]
mod tests {
    use super::{CookieMessage, DataHeader, HandshakeInit, HandshakeResp};
    use zerocopy::IntoBytes;

    #[repr(align(16))]
    struct AlignedPacket([u8; 1504]);

    #[test]
    fn data_message_accepts_arbitrary_payload_lengths() {
        let expected_header = DataHeader {
            _type: super::MSG_DATA.into(),
            receiver: 123.into(),
            counter: 456.into(),
        };
        // Includes keepalives, every length modulo 16, and full-MTU packets
        // whose padding is capped at 1420 rather than rounded up to 1424.
        for payload_len in 0..=1450 {
            let mut packet = AlignedPacket([0xa5; 1504]);
            packet.0[..16].copy_from_slice(expected_header.as_bytes());
            let message_len = 16 + payload_len + 16;
            let (header, payload_and_tag) =
                DataHeader::message_mut_from(&mut packet.0[..message_len])
                    .expect("complete transport message");
            assert_eq!(header.as_bytes(), expected_header.as_bytes());
            assert_eq!(payload_and_tag.len(), payload_len + 16);
            assert!(payload_and_tag.iter().all(|&byte| byte == 0xa5));
            payload_and_tag[0] = 0x5a;
            assert_eq!(packet.0[16], 0x5a);
        }
    }

    #[test]
    fn data_message_rejects_truncated_header_or_tag() {
        let mut packet = AlignedPacket([0; 1504]);
        for len in 0..32 {
            assert!(DataHeader::message_mut_from(&mut packet.0[..len]).is_none());
        }
        assert!(DataHeader::message_mut_from(&mut packet.0[..32]).is_some());
    }

    #[test]
    fn data_message_preserves_alignment_requirement() {
        let mut packet = AlignedPacket([0; 1504]);
        for offset in 1..16 {
            assert!(DataHeader::message_mut_from(&mut packet.0[offset..offset + 48]).is_none());
        }
    }

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
