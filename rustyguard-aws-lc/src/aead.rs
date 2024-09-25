// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::error::Unspecified;
use core::{fmt::Debug, ops::RangeFrom};

mod aead_ctx;
// mod aes_gcm;
mod chacha;
// pub mod chacha20_poly1305_openssh;
mod nonce;
// pub mod nonce_sequence;
// mod poly1305;
// pub mod quic;
// mod rand_nonce;
// mod tls;
// mod unbound_key;

pub use self::{
    chacha::ChaChaKey,
    nonce::{Nonce, NONCE_LEN},
};

/// The additionally authenticated data (AAD) for an opening or sealing
/// operation. This data is authenticated but is **not** encrypted.
///
/// The type `A` could be a byte slice `&[u8]`, a byte array `[u8; N]`
/// for some constant `N`, `Vec<u8>`, etc.
pub struct Aad<A: AsRef<[u8]>>(A);

impl<A: AsRef<[u8]>> Aad<A> {
    /// Construct the `Aad` from the given bytes.
    #[inline]
    pub fn from(aad: A) -> Self {
        Aad(aad)
    }
}

impl<A> AsRef<[u8]> for Aad<A>
where
    A: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Aad<[u8; 0]> {
    /// Construct an empty `Aad`.
    #[must_use]
    pub fn empty() -> Self {
        Self::from([])
    }
}

/// Immutable keys for use in situations where `OpeningKey`/`SealingKey` and
/// `NonceSequence` cannot reasonably be used.
///
/// Prefer [`RandomizedNonceKey`] when practical.
///
// # FIPS
// The following conditions must be met:
// * `UnboundKey`'s algorithm is one of:
//   * `AES_128_GCM`
//   * `AES_256_GCM`
// * Use `open_in_place` or `open_within` only.
pub struct LessSafeKey {
    key: ChaChaKey,
}

impl LessSafeKey {
    /// Constructs a `LessSafeKey` from an `UnboundKey`.
    #[must_use]
    pub fn new(key: ChaChaKey) -> Self {
        Self { key }
    }

    /// Like [`OpeningKey::open_in_place()`], except it accepts an arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to open data.
    ///
    /// Prefer [`RandomizedNonceKey::open_in_place`].
    ///
    // # FIPS
    // Use this method with one of the following algorithms:
    // * `AES_128_GCM`
    // * `AES_256_GCM`
    //
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid.
    #[inline]
    pub fn open_in_place<'in_out, A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.open_within(nonce, aad, in_out, 0..)
    }

    /// Like [`OpeningKey::open_within()`], except it accepts an arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to open data.
    ///
    /// Prefer [`RandomizedNonceKey::open_in_place`].
    ///
    // # FIPS
    // Use this method with one of the following algorithms:
    // * `AES_128_GCM`
    // * `AES_256_GCM`
    //
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn open_within<'in_out, A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.key
            .open_within(nonce, aad.as_ref(), in_out, ciphertext_and_tag)
    }

    /// Authenticates and decrypts (“opens”) data into another provided slice.
    ///
    /// `aad` is the additional authenticated data (AAD), if any.
    ///
    /// On input, `in_ciphertext` must be the ciphertext. The tag must be provided in
    /// `in_tag`.
    ///
    /// The `out_plaintext` length must match the provided `in_ciphertext`.
    ///
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid. In this case, `out_plaintext` may
    /// have been overwritten in an unspecified way.
    ///
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn open_separate_gather<A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_ciphertext: &[u8],
        in_tag: &[u8],
        out_plaintext: &mut [u8],
    ) -> Result<(), Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.key
            .open_separate_gather(&nonce, aad.as_ref(), in_ciphertext, in_tag, out_plaintext)
    }

    /// Deprecated. Renamed to `seal_in_place_append_tag()`.
    ///
    /// Prefer [`RandomizedNonceKey::seal_in_place_append_tag`].
    ///
    // # FIPS
    // This method must not be used.
    //
    #[deprecated(note = "Renamed to `seal_in_place_append_tag`.")]
    #[inline]
    #[allow(clippy::missing_errors_doc)]
    pub fn seal_in_place<A, InOut>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), Unspecified>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        self.seal_in_place_append_tag(nonce, aad, in_out)
    }

    /// Like [`SealingKey::seal_in_place_append_tag()`], except it accepts an
    /// arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to seal data.
    ///
    /// Prefer [`RandomizedNonceKey::seal_in_place_append_tag`].
    ///
    // # FIPS
    // This method must not be used.
    //
    /// # Errors
    /// `error::Unspecified` if encryption operation fails.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn seal_in_place_append_tag<A, InOut>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), Unspecified>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        self.key
            .seal_in_place_append_tag(Some(nonce), aad.as_ref(), in_out)
            .map(|_| ())
    }

    /// Like `SealingKey::seal_in_place_separate_tag()`, except it accepts an
    /// arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to seal data.
    ///
    /// Prefer [`RandomizedNonceKey::seal_in_place_separate_tag`].
    ///
    // # FIPS
    // This method must not be used.
    //
    /// # Errors
    /// `error::Unspecified` if encryption operation fails.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn seal_in_place_separate_tag<A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut [u8],
    ) -> Result<Tag, Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.key
            .seal_in_place_separate_tag(Some(nonce), aad.as_ref(), in_out)
            .map(|(_, tag)| tag)
    }

    /// Encrypts and signs (“seals”) data in place with extra plaintext.
    ///
    /// `aad` is the additional authenticated data (AAD), if any. This is
    /// authenticated but not encrypted. The type `A` could be a byte slice
    /// `&[u8]`, a byte array `[u8; N]` for some constant `N`, `Vec<u8>`, etc.
    /// If there is no AAD then use `Aad::empty()`.
    ///
    /// The plaintext is given as the input value of `in_out` and `extra_in`. `seal_in_place()`
    /// will overwrite the plaintext contained in `in_out` with the ciphertext. The `extra_in` will
    /// be encrypted into the `extra_out_and_tag`, along with the tag.
    /// The `extra_out_and_tag` length must be equal to the `extra_len` and `self.algorithm.tag_len()`.
    ///
    /// `nonce` must be unique for every use of the key to seal data.
    ///
    // # FIPS
    // This method must not be used.
    //
    /// # Errors
    /// `error::Unspecified` if encryption operation fails.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn seal_in_place_scatter<A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut [u8],
        extra_in: &[u8],
        extra_out_and_tag: &mut [u8],
    ) -> Result<(), Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.key.seal_in_place_separate_scatter(
            nonce,
            aad.as_ref(),
            in_out,
            extra_in,
            extra_out_and_tag,
        )
    }
}

impl Debug for LessSafeKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("LessSafeKey").finish()
    }
}

/// An authentication tag.
#[must_use]
#[repr(C)]
pub struct Tag([u8; MAX_TAG_LEN], usize);

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        self.0[..self.1].as_ref()
    }
}

#[allow(dead_code)]
const MAX_KEY_LEN: usize = 32;

// All the AEADs we support use 128-bit tags.
const TAG_LEN: usize = 16;

/// The maximum length of a tag for the algorithms in this module.
pub const MAX_TAG_LEN: usize = TAG_LEN;
