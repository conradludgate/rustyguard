// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use rustyguard_aws_lc::{aead, error, test, test_file};

use core::ops::RangeFrom;
use rustyguard_aws_lc::aead::{Nonce, NONCE_LEN};
use std::sync::OnceLock;

#[test]
fn aead_chacha20_poly1305() {
    test_aead(test_file!("data/aead_chacha20_poly1305_tests.txt"));
}

#[allow(clippy::too_many_lines)]
fn test_aead(test_file: test::File) {
    // TLS record headers are 5 bytes long.
    // TLS explicit nonces for AES-GCM are 8 bytes long.
    static MINIMAL_IN_PREFIX_LENS: [usize; 36] = [
        // No input prefix to overwrite; i.e. the opening is exactly
        // "in place."
        0,
        1,
        2,
        // Proposed TLS 1.3 header (no explicit nonce).
        5,
        8,
        // Probably the most common use of a non-zero `in_prefix_len`
        // would be to write a decrypted TLS record over the top of the
        // TLS header and nonce.
        5 /* record header */ + 8, /* explicit nonce */
        // The stitched AES-GCM x86-64 code works on 6-block (96 byte)
        // units. Some of the ChaCha20 code is even weirder.
        15,  // The maximum partial AES block.
        16,  // One AES block.
        17,  // One byte more than a full AES block.
        31,  // 2 AES blocks or 1 ChaCha20 block, minus 1.
        32,  // Two AES blocks, one ChaCha20 block.
        33,  // 2 AES blocks or 1 ChaCha20 block, plus 1.
        47,  // Three AES blocks - 1.
        48,  // Three AES blocks.
        49,  // Three AES blocks + 1.
        63,  // Four AES blocks or two ChaCha20 blocks, minus 1.
        64,  // Four AES blocks or two ChaCha20 blocks.
        65,  // Four AES blocks or two ChaCha20 blocks, plus 1.
        79,  // Five AES blocks, minus 1.
        80,  // Five AES blocks.
        81,  // Five AES blocks, plus 1.
        95,  // Six AES blocks or three ChaCha20 blocks, minus 1.
        96,  // Six AES blocks or three ChaCha20 blocks.
        97,  // Six AES blocks or three ChaCha20 blocks, plus 1.
        111, // Seven AES blocks, minus 1.
        112, // Seven AES blocks.
        113, // Seven AES blocks, plus 1.
        127, // Eight AES blocks or four ChaCha20 blocks, minus 1.
        128, // Eight AES blocks or four ChaCha20 blocks.
        129, // Eight AES blocks or four ChaCha20 blocks, plus 1.
        143, // Nine AES blocks, minus 1.
        144, // Nine AES blocks.
        145, // Nine AES blocks, plus 1.
        255, // 16 AES blocks or 8 ChaCha20 blocks, minus 1.
        256, // 16 AES blocks or 8 ChaCha20 blocks.
        257, // 16 AES blocks or 8 ChaCha20 blocks, plus 1.
    ];

    test_aead_key_sizes();

    test::run(test_file, |section, test_case| {
        assert_eq!(section, "");
        let key_bytes = test_case.consume_bytes("KEY");
        let nonce_bytes = test_case.consume_bytes("NONCE");
        let plaintext = test_case.consume_bytes("IN");
        let aad = test_case.consume_bytes("AD");
        let mut ct = test_case.consume_bytes("CT");
        let tag = test_case.consume_bytes("TAG");
        let error = test_case.consume_optional_string("FAILS");

        match &error {
            Some(err) if err == "WRONG_NONCE_LENGTH" => {
                assert!(Nonce::try_assume_unique_for_key(&nonce_bytes).is_err());
                return Ok(());
            }
            _ => (),
        };

        let mut s_in_out = plaintext.clone();
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
        let s_result = seal_with_less_safe_key(
            &key_bytes[..],
            nonce,
            aead::Aad::from(&aad[..]),
            &mut s_in_out,
        );

        ct.extend(tag);

        if s_result.is_ok() {
            assert_eq!(&ct, &s_in_out);
        }

        // In release builds, test all prefix lengths from 0 to 4096 bytes.
        // Debug builds are too slow for this, so for those builds, only
        // test a smaller subset.

        let mut more_comprehensive_in_prefix_lengths = [0; 4096];
        let in_prefix_lengths = if cfg!(debug_assertions) {
            &MINIMAL_IN_PREFIX_LENS[..]
        } else {
            #[allow(clippy::needless_range_loop)]
            for b in 0..more_comprehensive_in_prefix_lengths.len() {
                more_comprehensive_in_prefix_lengths[b] = b;
            }
            &more_comprehensive_in_prefix_lengths[..]
        };
        let mut o_in_out = vec![123u8; 4096];

        for &in_prefix_len in in_prefix_lengths {
            o_in_out.truncate(0);
            o_in_out.resize(in_prefix_len, 123);
            o_in_out.extend_from_slice(&ct[..]);

            let o_in_out_clone = o_in_out.clone();
            let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
            let o_result = open_with_less_safe_key(
                &key_bytes,
                nonce,
                aead::Aad::from(&aad[..]),
                &mut o_in_out,
                in_prefix_len..,
            );
            match error {
                None => {
                    assert!(s_result.is_ok());
                    assert!(o_result.is_ok(), "Not ok: {o_result:?}");
                    let result = o_result.unwrap();
                    assert_eq!(&plaintext[..], result);

                    for bad_func in [aead_open_bad_tag, aead_open_bad_nonce, aead_open_bad_aad] {
                        bad_func(
                            &key_bytes,
                            &nonce_bytes,
                            aad.as_slice(),
                            &o_in_out_clone,
                            in_prefix_len,
                        );
                    }
                }
                Some(ref error) if error == "WRONG_NONCE_LENGTH" => {
                    assert_eq!(Err(error::Unspecified), s_result);
                    assert_eq!(Err(error::Unspecified), o_result);
                }
                Some(error) => {
                    panic!("Unexpected error test case: {}", error);
                }
            };
        }

        Ok(())
    });
}

fn aead_open_bad_tag(
    key_bytes: &[u8],
    nonce_bytes: &[u8],
    aad_bytes: &[u8],
    in_out: &[u8],
    in_prefix_len: usize,
) {
    let mut in_out = Vec::from(in_out);
    let in_out_len = in_out.len();
    in_out[in_out_len - 1] ^= 0x08;
    let nonce_bytes = Vec::from(nonce_bytes);
    let aad_bytes = Vec::from(aad_bytes);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
    let aad = aead::Aad::from(aad_bytes.as_slice());
    let err_result = open_with_less_safe_key(key_bytes, nonce, aad, &mut in_out, in_prefix_len..);
    assert!(err_result.is_err());
}

fn aead_open_bad_nonce(
    key_bytes: &[u8],
    nonce_bytes: &[u8],
    aad_bytes: &[u8],
    in_out: &[u8],
    in_prefix_len: usize,
) {
    let mut in_out = Vec::from(in_out);
    let mut nonce_bytes = Vec::from(nonce_bytes);
    nonce_bytes[NONCE_LEN - 1] ^= 0x80;
    let aad_bytes = Vec::from(aad_bytes);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
    let aad = aead::Aad::from(aad_bytes.as_slice());
    let err_result = open_with_less_safe_key(key_bytes, nonce, aad, &mut in_out, in_prefix_len..);
    assert!(err_result.is_err());
}

fn aead_open_bad_aad(
    key_bytes: &[u8],
    nonce_bytes: &[u8],
    aad_bytes: &[u8],
    in_out: &[u8],
    in_prefix_len: usize,
) {
    let mut in_out = Vec::from(in_out);
    let nonce_bytes = Vec::from(nonce_bytes);
    let mut aad_bytes = Vec::from(aad_bytes);
    let aad_len = aad_bytes.len();
    if aad_len == 0 {
        aad_bytes.push(0x08);
    } else {
        aad_bytes[aad_len - 1] ^= 0x08;
    }
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
    let aad = aead::Aad::from(aad_bytes.as_slice());
    let err_result = open_with_less_safe_key(key_bytes, nonce, aad, &mut in_out, in_prefix_len..);
    assert!(err_result.is_err());
}

fn seal_with_less_safe_key(
    key: &[u8],
    nonce: Nonce,
    aad: aead::Aad<&[u8]>,
    in_out: &mut Vec<u8>,
) -> Result<(), error::Unspecified> {
    let key = make_less_safe_key(key);
    let tag = key.seal_in_place_separate_tag(nonce, aad, in_out)?;
    in_out.extend_from_slice(tag.as_ref());
    Ok(())
}

fn open_with_less_safe_key<'a>(
    key: &[u8],
    nonce: Nonce,
    aad: aead::Aad<&[u8]>,
    in_out: &'a mut [u8],
    ciphertext_and_tag: RangeFrom<usize>,
) -> Result<&'a mut [u8], error::Unspecified> {
    let key = make_less_safe_key(key);
    key.open_within(nonce, aad, in_out, ciphertext_and_tag)
}

#[allow(clippy::range_plus_one)]
fn test_aead_key_sizes() {
    let key_len = 32;
    let key_data = vec![1u8; key_len * 2];

    // Key is the right size.
    assert!(aead::ChaChaKey::new(&key_data[..key_len]).is_ok());

    // Key is one byte too small.
    assert!(aead::ChaChaKey::new(&key_data[..(key_len - 1)]).is_err());

    // Key is one byte too large.
    assert!(aead::ChaChaKey::new(&key_data[..(key_len + 1)]).is_err());

    // Key is half the required size.
    assert!(aead::ChaChaKey::new(&key_data[..(key_len / 2)]).is_err());

    // Key is twice the required size.
    assert!(aead::ChaChaKey::new(&key_data[..(key_len * 2)]).is_err());

    // Key is empty.
    assert!(aead::ChaChaKey::new(&[]).is_err());

    // Key is one byte.
    assert!(aead::ChaChaKey::new(&[0]).is_err());
}

// Test that we reject non-standard nonce sizes.
#[allow(clippy::range_plus_one)]
#[test]
fn test_aead_nonce_sizes() {
    let nonce_len = NONCE_LEN;
    let nonce = vec![0u8; nonce_len * 2];

    assert!(Nonce::try_assume_unique_for_key(&nonce[..nonce_len]).is_ok());
    assert!(Nonce::try_assume_unique_for_key(&nonce[..(nonce_len - 1)]).is_err());
    assert!(Nonce::try_assume_unique_for_key(&nonce[..(nonce_len + 1)]).is_err());
    assert!(Nonce::try_assume_unique_for_key(&nonce[..(nonce_len / 2)]).is_err());
    assert!(Nonce::try_assume_unique_for_key(&nonce[..(nonce_len * 2)]).is_err());
    assert!(Nonce::try_assume_unique_for_key(&[]).is_err());
    assert!(Nonce::try_assume_unique_for_key(&nonce[..1]).is_err());
    assert!(Nonce::try_assume_unique_for_key(&nonce[..16]).is_err()); // 128 bits.
}

#[test]
fn test_aead_traits() {
    test::compile_time_assert_send::<aead::Tag>();
    test::compile_time_assert_sync::<aead::Tag>();
    test::compile_time_assert_send::<aead::ChaChaKey>();
    test::compile_time_assert_sync::<aead::ChaChaKey>();
    test::compile_time_assert_send::<aead::LessSafeKey>();
    test::compile_time_assert_sync::<aead::LessSafeKey>();
}

#[test]
fn test_aead_thread_safeness() {
    static SECRET_KEY: OnceLock<aead::LessSafeKey> = OnceLock::new();
    SECRET_KEY
        .set(aead::LessSafeKey::new(
            aead::ChaChaKey::new(b"this is a test! this is a test! ").unwrap(),
        ))
        .unwrap();

    use std::thread;

    let tag = SECRET_KEY
        .get()
        .unwrap()
        .seal_in_place_separate_tag(
            Nonce::try_assume_unique_for_key(&[0; NONCE_LEN]).unwrap(),
            aead::Aad::empty(),
            &mut [],
        )
        .unwrap();

    let mut join_handles = Vec::new();
    for _ in 1..100 {
        let join_handle = thread::spawn(|| {
            SECRET_KEY
                .get()
                .unwrap()
                .seal_in_place_separate_tag(
                    Nonce::try_assume_unique_for_key(&[0; NONCE_LEN]).unwrap(),
                    aead::Aad::empty(),
                    &mut [],
                )
                .unwrap()
        });
        join_handles.push(join_handle);
    }
    for handle in join_handles {
        let thread_tag = handle.join().unwrap();
        assert_eq!(thread_tag.as_ref(), tag.as_ref());
    }
}

#[test]
fn test_aead_key_debug() {
    let key_bytes = [0; 32];

    let key = aead::ChaChaKey::new(&key_bytes).unwrap();
    assert_eq!("ChaChaKey", format!("{key:?}"));

    let key: aead::LessSafeKey = make_less_safe_key(&key_bytes);
    assert_eq!("LessSafeKey", format!("{key:?}"));
}

fn make_less_safe_key(key: &[u8]) -> aead::LessSafeKey {
    let key = aead::ChaChaKey::new(key).unwrap();
    aead::LessSafeKey::new(key)
}
