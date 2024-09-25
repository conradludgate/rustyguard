// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::error::Unspecified;
use core::{fmt::Debug, ops::RangeFrom};

mod aead_ctx;
mod chacha;
mod nonce;
mod xchacha;

pub use self::{
    chacha::ChaChaKey,
    nonce::{Nonce, XNonce, NONCE_LEN, XNONCE_LEN},
    xchacha::XChaChaKey,
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
        self.key.open_in_place(nonce, aad.as_ref(), in_out)
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
            .seal_in_place_separate_tag(nonce, aad.as_ref(), in_out)
            .map(|(_, tag)| tag)
    }
}

impl Debug for LessSafeKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("LessSafeKey").finish()
    }
}

pub struct XLessSafeKey {
    key: XChaChaKey,
}

impl XLessSafeKey {
    /// Constructs a `LessSafeKey` from an `UnboundKey`.
    #[must_use]
    pub fn new(key: XChaChaKey) -> Self {
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
        nonce: XNonce,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.key.open_in_place(nonce, aad.as_ref(), in_out)
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
        nonce: XNonce,
        aad: Aad<A>,
        in_out: &mut [u8],
    ) -> Result<Tag, Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.key
            .seal_in_place_separate_tag(nonce, aad.as_ref(), in_out)
            .map(|(_, tag)| tag)
    }
}

impl Debug for XLessSafeKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("XLessSafeKey").finish()
    }
}

/// An authentication tag.
#[must_use]
#[repr(C)]
pub struct Tag([u8; TAG_LEN]);

impl AsRef<[u8; TAG_LEN]> for Tag {
    fn as_ref(&self) -> &[u8; TAG_LEN] {
        &self.0
    }
}

#[allow(dead_code)]
const MAX_KEY_LEN: usize = 32;

// All the AEADs we support use 128-bit tags.
const TAG_LEN: usize = 16;
