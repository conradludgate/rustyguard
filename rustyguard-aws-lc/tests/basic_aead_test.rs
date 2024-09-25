// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

extern crate core;

use rustyguard_aws_lc::{
    aead::{self, ChaChaKey, LessSafeKey},
    test,
};

use aead::{Aad, Nonce};
use rustyguard_aws_lc::test::from_hex;

struct AeadConfig {
    key: Vec<u8>,
    nonce: Vec<u8>,
    aad: String,
}

impl AeadConfig {
    fn new(key: &[u8], nonce: &[u8], aad: &str) -> AeadConfig {
        AeadConfig {
            key: Vec::from(key),
            nonce: Vec::from(nonce),
            aad: String::from(aad),
        }
    }

    fn key(&self) -> ChaChaKey {
        ChaChaKey::new(&self.key).unwrap()
    }
    fn aad(&self) -> Aad<String> {
        Aad::from(self.aad.clone())
    }
}

#[test]
fn test_chacha20_poly1305() {
    let config = AeadConfig::new(
        &from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap(),
        &from_hex("070000004041424344454647").unwrap(),
        "123456789abcdef",
    );
    let in_out = from_hex("123456789abcdef0").unwrap();
    test_aead_append_within(&config, &in_out).unwrap();
}

fn test_aead_append_within(config: &AeadConfig, in_out: &[u8]) -> Result<Vec<u8>, String> {
    let sealing_key = LessSafeKey::new(config.key());

    println!("Sealing Key: {sealing_key:?}");

    let plaintext = in_out.to_owned();
    println!("Plaintext: {plaintext:?}");
    let mut sized_in_out = in_out.to_vec();
    sealing_key
        .seal_in_place_append_tag(
            Nonce::try_assume_unique_for_key(&config.nonce).unwrap(),
            config.aad(),
            &mut sized_in_out,
        )
        .map_err(|x| x.to_string())?;

    let (cipher_text, tag_value) = sized_in_out.split_at_mut(plaintext.len());

    if !plaintext.is_empty() {
        assert_ne!(plaintext, cipher_text);
    }
    println!("Ciphertext: {cipher_text:?}");
    println!("Tag: {tag_value:?}");

    let result_plaintext = sealing_key
        .open_within(
            Nonce::try_assume_unique_for_key(&config.nonce).unwrap(),
            config.aad(),
            &mut sized_in_out,
            0..,
        )
        .map_err(|x| x.to_string())?;

    assert_eq!(plaintext, result_plaintext);

    println!("Roundtrip: {result_plaintext:?}");

    Ok(Vec::from(result_plaintext))
}

#[test]
fn test_types() {
    test::compile_time_assert_send::<LessSafeKey>();
    test::compile_time_assert_sync::<LessSafeKey>();
}
