// Copyright 2015-2017 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

mod ephemeral;

pub use ephemeral::{agree_ephemeral, EphemeralPrivateKey};

use crate::error::{KeyRejected, Unspecified};
use crate::hex;
use crate::ptr::LcPtr;
use aws_lc::{
    CBS_init, EVP_PKEY_CTX_new_id, EVP_PKEY_derive, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer,
    EVP_PKEY_get_raw_private_key, EVP_PKEY_get_raw_public_key, EVP_PKEY_id, EVP_PKEY_keygen,
    EVP_PKEY_keygen_init, EVP_PKEY_new_raw_private_key, EVP_PKEY_new_raw_public_key,
    EVP_parse_public_key, CBS, EVP_PKEY, EVP_PKEY_X25519,
};

use core::fmt;
use core::fmt::{Debug, Formatter};
use core::mem::MaybeUninit;
use core::ptr::null_mut;

/// A private key for use (only) with `agree`. The
/// signature of `agree` allows `PrivateKey` to be
/// used for more than one key agreement.
pub struct PrivateKey {
    inner_key: LcPtr<EVP_PKEY>,
}

unsafe impl Send for PrivateKey {}

// https://github.com/awslabs/aws-lc/blob/main/include/openssl/ec_key.h#L88
// An |EC_KEY| object represents a public or private EC key. A given object may
// be used concurrently on multiple threads by non-mutating functions, provided
// no other thread is concurrently calling a mutating function. Unless otherwise
// documented, functions which take a |const| pointer are non-mutating and
// functions which take a non-|const| pointer are mutating.
unsafe impl Sync for PrivateKey {}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "PrivateKey",)
    }
}

impl PrivateKey {
    fn new(evp_pkey: LcPtr<EVP_PKEY>) -> Self {
        Self {
            inner_key: evp_pkey,
        }
    }

    #[inline]
    /// Generate a new private key for the given algorithm.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn generate() -> Result<Self, Unspecified> {
        Ok(Self::new(generate_x25519()?))
    }

    /// Constructs an ECDH key from private key bytes
    ///
    /// The private key must encoded as a big-endian fixed-length integer. For
    /// example, a P-256 private key must be 32 bytes prefixed with leading
    /// zeros as needed.
    ///
    /// # Errors
    /// `error::KeyRejected` if parsing failed or key otherwise unacceptable.
    pub fn from_private_key(key_bytes: &[u8]) -> Result<Self, KeyRejected> {
        if key_bytes.len() != 32 {
            return Err(KeyRejected::wrong_algorithm());
        }
        let evp_pkey = LcPtr::new(unsafe {
            EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, null_mut(), key_bytes.as_ptr(), 32)
        })?;

        Ok(Self::new(evp_pkey))
    }

    pub fn as_bytes(&self) -> Result<[u8; 32], Unspecified> {
        let evp_pkey = self.inner_key.as_const();
        let mut buffer = [0u8; 32];
        let mut out_len = 32;
        if unsafe {
            EVP_PKEY_get_raw_private_key(*evp_pkey, buffer.as_mut_ptr(), &mut out_len) != 1
        } {
            return Err(Unspecified);
        }
        debug_assert_eq!(32, out_len);
        Ok(buffer)
    }

    #[cfg(test)]
    #[allow(clippy::missing_errors_doc, missing_docs)]
    pub fn generate_for_test(rng: &dyn crate::rand::SecureRandom) -> Result<Self, Unspecified> {
        let mut priv_key = [0u8; 32];
        rng.fill(&mut priv_key)?;
        Self::from_x25519_private_key(&priv_key)
    }

    #[cfg(test)]
    fn from_x25519_private_key(priv_key: &[u8; 32]) -> Result<Self, Unspecified> {
        let pkey = LcPtr::new(unsafe {
            EVP_PKEY_new_raw_private_key(
                EVP_PKEY_X25519,
                null_mut(),
                priv_key.as_ptr(),
                priv_key.len(),
            )
        })?;

        Ok(PrivateKey { inner_key: pkey })
    }

    /// Computes the public key from the private key.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn compute_public_key(&self) -> Result<PublicKey, Unspecified> {
        let mut buffer = [0u8; MAX_PUBLIC_KEY_LEN];
        let mut out_len = buffer.len();

        if 1 != unsafe {
            EVP_PKEY_get_raw_public_key(
                *self.inner_key.as_const(),
                buffer.as_mut_ptr(),
                &mut out_len,
            )
        } {
            return Err(Unspecified);
        }

        assert_eq!(out_len, 32);

        Ok(PublicKey {
            inner_key: self.inner_key.clone(),
            public_key: buffer,
        })
    }
}

pub(crate) fn generate_x25519() -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let mut pkey_ctx = LcPtr::new(unsafe { EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, null_mut()) })?;

    if 1 != unsafe { EVP_PKEY_keygen_init(*pkey_ctx.as_mut()) } {
        return Err(Unspecified);
    }

    let mut pkey: *mut EVP_PKEY = null_mut();

    if 1 != (unsafe { EVP_PKEY_keygen(*pkey_ctx.as_mut(), &mut pkey) }) {
        return Err(Unspecified);
    }

    let pkey = LcPtr::new(pkey)?;

    Ok(pkey)
}

const MAX_PUBLIC_KEY_LEN: usize = 32;

/// A public key for key agreement.
pub struct PublicKey {
    inner_key: LcPtr<EVP_PKEY>,
    public_key: [u8; MAX_PUBLIC_KEY_LEN],
}

unsafe impl Send for PublicKey {}
unsafe impl Sync for PublicKey {}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "PublicKey {{ bytes: \"{}\" }}",
            hex::encode(self.public_key)
        )
    }
}

impl AsRef<[u8; 32]> for PublicKey {
    /// Serializes the public key in an uncompressed form (X9.62) using the
    /// Octet-String-to-Elliptic-Curve-Point algorithm in
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0].
    fn as_ref(&self) -> &[u8; 32] {
        &self.public_key
    }
}

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        PublicKey {
            inner_key: self.inner_key.clone(),
            public_key: self.public_key,
        }
    }
}

/// An unparsed, possibly malformed, public key for key agreement.
#[derive(Clone, Copy)]
pub struct UnparsedPublicKey {
    bytes: [u8; 32],
}

impl Debug for UnparsedPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "UnparsedPublicKey {{ bytes: {:?} }}",
            hex::encode(self.bytes.as_ref())
        )
    }
}

impl UnparsedPublicKey {
    /// Constructs a new `UnparsedPublicKey`.
    pub fn new(bytes: [u8; 32]) -> Self {
        UnparsedPublicKey { bytes }
    }

    /// The bytes provided for this public key
    pub fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Performs a key agreement with a private key and the given public key.
///
/// `my_private_key` is the private key to use. Only a reference to the key
/// is required, allowing the key to continue to be used.
///
/// `peer_public_key` is the peer's public key. `agree` will return
/// `Err(error_value)` if it does not match `my_private_key's` algorithm/curve.
/// `agree` verifies that it is encoded in the standard form for the
/// algorithm and that the key is *valid*; see the algorithm's documentation for
/// details on how keys are to be encoded and what constitutes a valid key for
/// that algorithm.
///
/// `error_value` is the value to return if an error occurs before `kdf` is
/// called, e.g. when decoding of the peer's public key fails or when the public
/// key is otherwise invalid.
///
/// After the key agreement is done, `agree` calls `kdf` with the raw
/// key material from the key agreement operation and then returns what `kdf`
/// returns.
///
/// # Errors
/// `error_value` on internal failure.
#[inline]
#[allow(clippy::missing_panics_doc)]
pub fn agree<F, R, E>(
    my_private_key: &PrivateKey,
    peer_public_key: &UnparsedPublicKey,
    error_value: E,
    kdf: F,
) -> Result<R, E>
where
    F: FnOnce(&[u8]) -> Result<R, E>,
{
    let peer_pub_bytes = peer_public_key.bytes.as_ref();

    let mut buffer = [0u8; MAX_AGREEMENT_SECRET_LEN];

    let secret: &[u8] =
        x25519_diffie_hellman(&mut buffer, &my_private_key.inner_key, peer_pub_bytes)
            .or(Err(error_value))?;

    kdf(secret)
}

const MAX_AGREEMENT_SECRET_LEN: usize = 32;

#[inline]
fn x25519_diffie_hellman<'a>(
    buffer: &'a mut [u8; MAX_AGREEMENT_SECRET_LEN],
    priv_key: &LcPtr<EVP_PKEY>,
    peer_pub_key: &[u8],
) -> Result<&'a [u8], ()> {
    let mut pkey_ctx = priv_key.create_EVP_PKEY_CTX()?;

    if 1 != unsafe { EVP_PKEY_derive_init(*pkey_ctx.as_mut()) } {
        return Err(());
    };

    let mut pub_key = try_parse_x25519_public_key_bytes(peer_pub_key)?;

    if 1 != unsafe { EVP_PKEY_derive_set_peer(*pkey_ctx.as_mut(), *pub_key.as_mut()) } {
        return Err(());
    }

    let mut out_key_len = buffer.len();

    if 1 != (unsafe { EVP_PKEY_derive(*pkey_ctx.as_mut(), buffer.as_mut_ptr(), &mut out_key_len) })
    {
        return Err(());
    }

    Ok(&buffer[..])
}

pub(crate) fn try_parse_x25519_public_key_bytes(
    key_bytes: &[u8],
) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    try_parse_x25519_subject_public_key_info_bytes(key_bytes)
        .or(try_parse_x25519_public_key_raw_bytes(key_bytes))
}

fn try_parse_x25519_public_key_raw_bytes(key_bytes: &[u8]) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let expected_pub_key_len = 32;
    if key_bytes.len() != expected_pub_key_len {
        return Err(Unspecified);
    }

    Ok(LcPtr::new(unsafe {
        EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519,
            null_mut(),
            key_bytes.as_ptr(),
            key_bytes.len(),
        )
    })?)
}

fn try_parse_x25519_subject_public_key_info_bytes(
    key_bytes: &[u8],
) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    // Try to parse as SubjectPublicKeyInfo first
    let mut cbs = {
        let mut cbs = MaybeUninit::<CBS>::uninit();
        unsafe {
            CBS_init(cbs.as_mut_ptr(), key_bytes.as_ptr(), key_bytes.len());
            cbs.assume_init()
        }
    };
    let evp_pkey = LcPtr::new(unsafe { EVP_parse_public_key(&mut cbs) })?;
    if EVP_PKEY_X25519 != unsafe { EVP_PKEY_id(*evp_pkey.as_const()) } {
        return Err(Unspecified);
    }
    Ok(evp_pkey)
}

#[cfg(test)]
mod tests {
    use crate::agreement::{agree, PrivateKey, PublicKey, UnparsedPublicKey};
    use crate::{rand, test};

    use std::vec::Vec;
    use std::{format, vec};

    #[test]
    fn test_agreement_x25519() {
        let peer_public = UnparsedPublicKey::new(
            test::from_dirty_hex(
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            )
            .try_into()
            .unwrap(),
        );

        let my_private = test::from_dirty_hex(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        );

        let my_private = {
            let rng = test::rand::FixedSliceRandom { bytes: &my_private };
            PrivateKey::generate_for_test(&rng).unwrap()
        };

        let my_public = test::from_dirty_hex(
            "1c9fd88f45606d932a80c71824ae151d15d73e77de38e8e000852e614fae7019",
        );
        let output = test::from_dirty_hex(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        );

        let be_private_key_buffer = my_private.as_bytes().unwrap();
        let be_private_key = PrivateKey::from_private_key(be_private_key_buffer.as_ref()).unwrap();
        {
            let result = agree(&be_private_key, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }

        let computed_public = my_private.compute_public_key().unwrap();
        assert_eq!(computed_public.as_ref(), &my_public[..]);

        {
            let result = agree(&my_private, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }
        {
            let result = agree(&my_private, &peer_public, (), |key_material| {
                assert_eq!(key_material, &output[..]);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }
    }

    #[test]
    fn agreement_traits() {
        use crate::test;
        use regex;
        use regex::Regex;

        let rng = rand::SystemRandom::new();
        let private_key = PrivateKey::generate_for_test(&rng).unwrap();

        test::compile_time_assert_send::<PrivateKey>();
        test::compile_time_assert_sync::<PrivateKey>();

        assert_eq!(format!("{:?}", &private_key), "PrivateKey");

        let ephemeral_private_key = PrivateKey::generate_for_test(&rng).unwrap();

        test::compile_time_assert_send::<PrivateKey>();
        test::compile_time_assert_sync::<PrivateKey>();

        assert_eq!(format!("{:?}", &ephemeral_private_key), "PrivateKey");

        let public_key = private_key.compute_public_key().unwrap();
        let pubkey_re = Regex::new("PublicKey \\{ bytes: \"[0-9a-f]+\" \\}").unwrap();
        let pubkey_debug = format!("{:?}", &public_key);

        assert!(
            pubkey_re.is_match(&pubkey_debug),
            "pubkey_debug: {pubkey_debug}"
        );

        #[allow(clippy::redundant_clone)]
        let pubkey_clone = public_key.clone();
        assert_eq!(public_key.as_ref(), pubkey_clone.as_ref());
        assert_eq!(pubkey_debug, format!("{:?}", &pubkey_clone));

        test::compile_time_assert_clone::<PublicKey>();
        test::compile_time_assert_send::<PublicKey>();
        test::compile_time_assert_sync::<PublicKey>();

        // Verify `PublicKey` implements `Debug`.
        let _: &dyn core::fmt::Debug = &public_key;

        test::compile_time_assert_clone::<UnparsedPublicKey>();
        test::compile_time_assert_copy::<UnparsedPublicKey>();
        test::compile_time_assert_sync::<UnparsedPublicKey>();
    }

    #[test]
    fn test_agreement_random() {
        let peer_private = PrivateKey::generate().unwrap();
        let my_private = PrivateKey::generate().unwrap();

        let peer_public_keys =
            public_key_formats_helper(&peer_private.compute_public_key().unwrap());

        let my_public_keys = public_key_formats_helper(&my_private.compute_public_key().unwrap());

        let mut results: Vec<Vec<u8>> = Vec::new();

        for peer_public in peer_public_keys {
            let peer_public = UnparsedPublicKey::new(peer_public);
            let result = agree(&my_private, &peer_public, (), |key_material| {
                results.push(key_material.to_vec());
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }

        for my_public in my_public_keys {
            let my_public = UnparsedPublicKey::new(my_public);
            let result = agree(&peer_private, &my_public, (), |key_material| {
                results.push(key_material.to_vec());
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }

        assert_eq!(results.len(), 2); // Multiplied by two because we tested the other direction
        assert_eq!(results[0..1], results[1..]);
    }

    fn public_key_formats_helper(public_key: &PublicKey) -> Vec<[u8; 32]> {
        vec![*public_key.as_ref()]
    }

    #[test]
    fn private_key_drop() {
        let private_key = PrivateKey::generate().unwrap();
        let public_key = private_key.compute_public_key().unwrap();
        // PublicKey maintains a reference counted pointer to private keys EVP_PKEY so we test that with drop
        drop(private_key);
        let _ = public_key.as_ref();
        // let _ = AsBigEndian::<EcPublicKeyUncompressedBin>::as_be_bytes(&public_key).unwrap();
        // let _ = AsDer::<PublicKeyX509Der>::as_der(&public_key).unwrap();
    }
}
