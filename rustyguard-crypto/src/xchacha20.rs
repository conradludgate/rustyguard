//! XChaCha is an extended nonce variant of ChaCha

// Source modified from <https://github.com/RustCrypto/stream-ciphers/blob/5c7892d0b25a43de9a844e012f11ebaebdd3bc33/chacha20/src/xchacha.rs>
// Licensed under MIT or Apache-2.0

/// State initialization constant ("expand 32-byte k")
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Number of 32-bit words in the ChaCha state
const STATE_WORDS: usize = 16;

use graviola::aead::ChaCha20Poly1305;

use crate::Key;

pub(crate) fn new_xchacha20(key: &Key, iv: &[u8; 24]) -> (ChaCha20Poly1305, [u8; 12]) {
    let subkey = hchacha(key, iv[..16].as_ref().try_into().unwrap());
    let mut padded_iv = [0u8; 12];
    padded_iv[4..].copy_from_slice(&iv[16..]);
    (ChaCha20Poly1305::new(subkey), padded_iv)
}

/// The HChaCha function: adapts the ChaCha core function in the same
/// manner that HSalsa adapts the Salsa function.
///
/// HChaCha takes 512-bits of input:
///
/// - Constants: `u32` x 4
/// - Key: `u32` x 8
/// - Nonce: `u32` x 4
///
/// It produces 256-bits of output suitable for use as a ChaCha key
///
/// For more information on HSalsa on which HChaCha is based, see:
///
/// <http://cr.yp.to/snuffle/xsalsa-20110204.pdf>
pub fn hchacha(key: &Key, input: &[u8; 16]) -> [u8; 32] {
    let mut state = [0u32; STATE_WORDS];
    state[..4].copy_from_slice(&CONSTANTS);

    let key_chunks = key.chunks_exact(4);
    for (v, chunk) in state[4..12].iter_mut().zip(key_chunks) {
        *v = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    let input_chunks = input.chunks_exact(4);
    for (v, chunk) in state[12..16].iter_mut().zip(input_chunks) {
        *v = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    // R rounds consisting of R/2 column rounds and R/2 diagonal rounds
    for _ in 0..10 {
        // column rounds
        quarter_round(0, 4, 8, 12, &mut state);
        quarter_round(1, 5, 9, 13, &mut state);
        quarter_round(2, 6, 10, 14, &mut state);
        quarter_round(3, 7, 11, 15, &mut state);

        // diagonal rounds
        quarter_round(0, 5, 10, 15, &mut state);
        quarter_round(1, 6, 11, 12, &mut state);
        quarter_round(2, 7, 8, 13, &mut state);
        quarter_round(3, 4, 9, 14, &mut state);
    }

    let mut output = [0u8; 32];

    for (chunk, val) in output[..16].chunks_exact_mut(4).zip(&state[..4]) {
        chunk.copy_from_slice(&val.to_le_bytes());
    }

    for (chunk, val) in output[16..].chunks_exact_mut(4).zip(&state[12..]) {
        chunk.copy_from_slice(&val.to_le_bytes());
    }

    output
}

/// The ChaCha20 quarter round function
// for simplicity this function is copied from the software backend
fn quarter_round(a: usize, b: usize, c: usize, d: usize, state: &mut [u32; STATE_WORDS]) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

#[cfg(test)]
mod hchacha20_tests {
    use super::*;

    /// Test vectors from:
    /// https://tools.ietf.org/id/draft-arciszewski-xchacha-03.html#rfc.section.2.2.1
    #[test]
    fn test_vector() {
        const KEY: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        const INPUT: [u8; 16] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41,
            0x59, 0x27,
        ];

        const OUTPUT: [u8; 32] = [
            0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe, 0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87,
            0x7d, 0x73, 0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53, 0xc1, 0x2e, 0xc4, 0x13,
            0x26, 0xd3, 0xec, 0xdc,
        ];

        let actual = hchacha(&KEY, &INPUT);
        assert_eq!(actual.as_slice(), &OUTPUT);
    }
}
