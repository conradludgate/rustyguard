use blake2::digest::consts::U32;
use blake2::digest::generic_array::ArrayLength;
use blake2::digest::generic_array::GenericArray;
use blake2::digest::{Digest, Output};
use blake2::Blake2s256;
use bytemuck::{Pod, TransparentWrapper, Zeroable};
use chacha20poly1305::consts::U16;
use chacha20poly1305::Nonce;
use hkdf::SimpleHkdfExtract;
use std::ops::Add;

pub(crate) fn nonce(counter: u64) -> Nonce {
    let mut n = Nonce::default();
    n[4..].copy_from_slice(&u64::to_le_bytes(counter));
    n
}

pub(crate) fn hash<const M: usize>(msg: [&[u8]; M]) -> Output<Blake2s256> {
    let mut digest = Blake2s256::default();
    for msg in msg {
        digest.update(msg);
    }
    digest.finalize()
}

// fn hmac<const M: usize>(key: &GenericArray<u8, U32>, msg: [&[u8]; M]) -> Output<Blake2s256> {
//     use hkdf::hmac::Mac;
//     let mut hmac = <SimpleHmac<Blake2s256> as Mac>::new_from_slice(key).unwrap();
//     for msg in msg {
//         hmac.update(msg);
//     }
//     hmac.finalize().into_bytes()
// }

// fn hmac<const M: usize>(key: &GenericArray<u8, U32>, msg: [&[u8]; M]) -> Output<Blake2s256> {
//     const IPAD: u8 = 0x36;
//     const OPAD: u8 = 0x5C;

//     let mut buf = Block::<Blake2s256>::default();
//     buf[..32].copy_from_slice(key);
//     for b in buf.iter_mut() {
//         *b ^= IPAD;
//     }
//     let mut digest = Blake2s256::default();
//     digest.update(&buf);

//     for b in buf.iter_mut() {
//         *b ^= IPAD ^ OPAD;
//     }

//     let mut opad_digest = Blake2s256::default();
//     opad_digest.update(&buf);

//     for msg in msg {
//         digest.update(msg);
//     }

//     opad_digest.chain_update(digest.finalize()).finalize()
// }

pub(crate) fn hkdf<const N: usize, const M: usize>(
    key: &GenericArray<u8, U32>,
    msg: [&[u8]; M],
) -> [Output<Blake2s256>; N] {
    let mut extract = SimpleHkdfExtract::<Blake2s256>::new(Some(key));
    for msg in msg {
        extract.input_ikm(msg);
    }
    let hkdf = extract.finalize().1;

    let mut output = [Output::<Blake2s256>::default(); N];
    let output2 = Bytes::wrap_slice_mut(&mut output);
    let output3 = bytemuck::cast_slice_mut::<_, u8>(output2);

    hkdf.expand(&[], output3).unwrap();

    // let (_, mut hkdf) = SimpleHkdf::<Blake2s256>::extract(Some(&key), &input);

    // hkdf.expand_multi_info(&[], okm)
    // hkdf.expand_multi_info(&msg, okm)

    // assert!(N <= 255);
    // assert!(N >= 1);

    // let t0 = hmac(key, msg);
    // let mut ti = hmac(&t0, [&[1]]);
    // output[0] = ti;
    // for i in 1..N as u8 {
    //     ti = hmac(&t0, [&ti, &[i + 1]]);
    //     output[i as usize] = ti;
    // }

    output
}

#[derive(Clone, TransparentWrapper)]
#[repr(transparent)]
pub(crate) struct Bytes<U: ArrayLength<u8>>(pub GenericArray<u8, U>);
impl<U: ArrayLength<u8>> Copy for Bytes<U> where GenericArray<u8, U>: Copy {}

// SAFETY: bytes are plain-old-data
unsafe impl<U: ArrayLength<u8>> Pod for Bytes<U> where GenericArray<u8, U>: Copy {}
// SAFETY: bytes are zeroable
unsafe impl<U: ArrayLength<u8>> Zeroable for Bytes<U> {}

pub(crate) type Encrypted<U> = <U as Add<U16>>::Output;

#[derive(Pod, Zeroable, Clone, Copy)]
#[repr(C)]
pub(crate) struct LEU32(u32);

impl LEU32 {
    pub(crate) fn get(self) -> u32 {
        u32::from_le(self.0)
    }
    pub(crate) fn new(n: u32) -> Self {
        Self(n.to_le())
    }
}
