// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use rand_core::{CryptoRng, RngCore};

use crate::agreement::{agree, PrivateKey, PublicKey, UnparsedPublicKey};
use crate::error::Unspecified;
use core::fmt;
use core::fmt::{Debug, Formatter};

/// An ephemeral private key for use (only) with `agree_ephemeral`. The
/// signature of `agree_ephemeral` ensures that an `PrivateKey` can be
/// used for at most one key agreement.
#[allow(clippy::module_name_repetitions)]
pub struct EphemeralPrivateKey(PrivateKey);

impl Debug for EphemeralPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "EphemeralPrivateKey",)
    }
}

impl EphemeralPrivateKey {
    #[inline]
    /// Generate a new ephemeral private key for the given algorithm.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self, Unspecified> {
        Ok(Self(PrivateKey::generate(rng)?))
    }

    /// Computes the public key from the private key.
    ///
    /// # Errors
    /// `error::Unspecified` when operation fails due to internal error.
    pub fn compute_public_key(&self) -> Result<PublicKey, Unspecified> {
        self.0.compute_public_key()
    }
}

/// Performs a key agreement with an ephemeral private key and the given public
/// key.
///
/// `my_private_key` is the ephemeral private key to use.
///
/// `peer_public_key` is the peer's public key. `agree_ephemeral` will return
/// `Err(error_value)` if it does not match `my_private_key's` algorithm/curve.
/// `agree_ephemeral` verifies that it is encoded in the standard form for the
/// algorithm and that the key is *valid*; see the algorithm's documentation for
/// details on how keys are to be encoded and what constitutes a valid key for
/// that algorithm.
///
/// After the key agreement is done, `agree_ephemeral` calls `kdf` with the raw
/// key material from the key agreement operation and then returns what `kdf`
/// returns.
///
/// # Errors
/// `error_value` on internal failure.
#[inline]
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::module_name_repetitions)]
pub fn agree_ephemeral<F, R>(
    my_private_key: &EphemeralPrivateKey,
    peer_public_key: &UnparsedPublicKey,
    kdf: F,
) -> Result<R, Unspecified>
where
    F: FnOnce(&[u8]) -> R,
{
    agree(&my_private_key.0, peer_public_key, kdf)
}

#[cfg(test)]
mod tests {
    use std::format;
    use std::vec::Vec;

    use rand::thread_rng;
    use rand_core::OsRng;

    use crate::agreement::PublicKey;
    use crate::error::Unspecified;
    use crate::{agreement, test, test_file};

    #[test]
    fn test_agreement_ecdh_x25519_rfc_iterated() {
        fn expect_iterated_x25519(
            expected_result: &str,
            range: core::ops::Range<usize>,
            k: &mut Vec<u8>,
            u: &mut Vec<u8>,
        ) {
            for _ in range {
                let new_k = x25519(k, u);
                u.clone_from(k);
                *k = new_k;
            }
            assert_eq!(&from_hex(expected_result), k);
        }

        let mut k = from_hex("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = k.clone();

        expect_iterated_x25519(
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
            0..1,
            &mut k,
            &mut u,
        );
        expect_iterated_x25519(
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
            1..1_000,
            &mut k,
            &mut u,
        );

        // The spec gives a test vector for 1,000,000 iterations but it takes
        // too long to do 1,000,000 iterations by default right now. This
        // 10,000 iteration vector is self-computed.
        expect_iterated_x25519(
            "2c125a20f639d504a7703d2e223c79a79de48c4ee8c23379aa19a62ecd211815",
            1_000..10_000,
            &mut k,
            &mut u,
        );
        /*
               expect_iterated_x25519(
                   "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424",
                   10_000..1_000_000,
                   &mut k,
                   &mut u,
               );
        */
    }

    #[test]
    fn test_agreement_x25519() {
        let peer_public = agreement::UnparsedPublicKey::new(
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
            let mut rng = test::rand::FixedSliceRandom { bytes: &my_private };
            agreement::EphemeralPrivateKey::generate(&mut rng).unwrap()
        };

        let my_public = test::from_dirty_hex(
            "1c9fd88f45606d932a80c71824ae151d15d73e77de38e8e000852e614fae7019",
        );
        let output = test::from_dirty_hex(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        );

        let computed_public = my_private.compute_public_key().unwrap();
        assert_eq!(computed_public.as_ref(), &my_public[..]);

        let result = agreement::agree_ephemeral(&my_private, &peer_public, |key_material| {
            assert_eq!(key_material, &output[..]);
        });
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn agreement_traits() {
        use crate::test;

        let ephemeral_private_key = agreement::EphemeralPrivateKey::generate(&mut OsRng).unwrap();

        test::compile_time_assert_send::<agreement::EphemeralPrivateKey>();
        test::compile_time_assert_sync::<agreement::EphemeralPrivateKey>();

        assert_eq!(
            format!("{:?}", &ephemeral_private_key),
            "EphemeralPrivateKey"
        );
    }

    fn check_computed_public_key(
        expected_format: &str,
        expected_public_key_bytes: &[u8],
        computed_public: &PublicKey,
    ) {
        match expected_format {
            "X509" => {}
            "" => {
                assert_eq!(expected_public_key_bytes, computed_public.as_ref());
            }
            pf => {
                panic!("Unexpected PeerFormat={pf:?}")
            }
        }
    }

    #[test]
    fn agreement_agree_ephemeral() {
        test::run(
            test_file!("data/agreement_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let curve_name = test_case.consume_string("Curve");
                assert_eq!(curve_name, "X25519");

                let mut peer_public = test_case.consume_bytes("PeerQ");
                if peer_public.len() != 32 {
                    peer_public = [0; 32].to_vec();
                }

                let peer_public =
                    agreement::UnparsedPublicKey::new(peer_public.try_into().unwrap());

                let myq_format = test_case
                    .consume_optional_string("MyQFormat")
                    .unwrap_or_default();

                if test_case.consume_optional_string("Error").is_none() {
                    let my_private_bytes = test_case.consume_bytes("D");
                    let my_private = {
                        let mut rng = test::rand::FixedSliceRandom {
                            bytes: &my_private_bytes,
                        };
                        agreement::EphemeralPrivateKey::generate(&mut rng)?
                    };
                    let my_public = test_case.consume_bytes("MyQ");
                    let output = test_case.consume_bytes("Output");

                    let computed_public = my_private.compute_public_key().unwrap();

                    check_computed_public_key(&myq_format, &my_public, &computed_public);

                    let result =
                        agreement::agree_ephemeral(&my_private, &peer_public, |key_material| {
                            assert_eq!(key_material, &output[..]);
                        });
                    assert_eq!(
                        result,
                        Ok(()),
                        "Failed on private key: {:?}",
                        test::to_hex(my_private_bytes)
                    );
                } else {
                    fn kdf_not_called(_: &[u8]) {
                        panic!(
                            "The KDF was called during ECDH when the peer's \
                         public key is invalid."
                        );
                    }
                    let dummy_private_key =
                        agreement::EphemeralPrivateKey::generate(&mut thread_rng())?;
                    assert!(agreement::agree_ephemeral(
                        &dummy_private_key,
                        &peer_public,
                        kdf_not_called
                    )
                    .is_err());
                }

                Ok(())
            },
        );
    }

    fn from_hex(s: &str) -> Vec<u8> {
        match test::from_hex(s) {
            Ok(v) => v,
            Err(msg) => {
                panic!("{msg} in {s}");
            }
        }
    }

    fn x25519(private_key: &[u8], public_key: &[u8]) -> Vec<u8> {
        try_x25519(private_key, public_key).unwrap()
    }

    fn try_x25519(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, Unspecified> {
        let mut rng = test::rand::FixedSliceRandom { bytes: private_key };
        let private_key = agreement::EphemeralPrivateKey::generate(&mut rng)?;
        let public_key = agreement::UnparsedPublicKey::new(public_key.try_into().unwrap());
        agreement::agree_ephemeral(&private_key, &public_key, |agreed_value| {
            Vec::from(agreed_value)
        })
    }
}
