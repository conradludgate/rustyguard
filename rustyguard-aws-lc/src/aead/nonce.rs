// Copyright 2018 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// use crate::endian::{ArrayEncoding, BigEndian, Encoding, FromArray, LittleEndian};
use crate::error;

/// A nonce for a single AEAD opening or sealing operation.
///
/// The user must ensure, for a particular key, that each nonce is unique.
///
/// `Nonce` intentionally doesn't implement `Clone` to ensure that each one is
/// consumed at most once.
pub struct Nonce(pub(crate) [u8; NONCE_LEN]);

impl Nonce {
    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    ///
    /// Fails if `value` isn't `NONCE_LEN` bytes long.
    /// # Errors
    /// `error::Unspecified` when byte slice length is not `NONCE_LEN`
    #[inline]
    pub fn try_assume_unique_for_key(value: &[u8]) -> Result<Self, error::Unspecified> {
        Ok(Self(value.try_into()?))
    }

    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    #[inline]
    #[must_use]
    pub fn assume_unique_for_key(value: [u8; NONCE_LEN]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8; NONCE_LEN]> for Nonce {
    #[inline]
    fn as_ref(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

impl From<&[u8; NONCE_LEN]> for Nonce {
    #[inline]
    fn from(bytes: &[u8; NONCE_LEN]) -> Self {
        Self(*bytes)
    }
}

/// All the AEADs we support use 96-bit nonces.
pub const NONCE_LEN: usize = 96 / 8;
