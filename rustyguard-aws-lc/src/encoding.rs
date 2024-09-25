// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Serialization formats

use crate::buffer::Buffer;
use alloc::vec::Vec;

use core::fmt::{Debug, Error, Formatter};
use core::ops::Deref;

mod buffer_type {
    pub struct Curve25519SeedBinType {
        _priv: (),
    }
}

pub struct Curve25519SeedBin<'a>(Buffer<'a, buffer_type::Curve25519SeedBinType>);

impl<'a> Deref for Curve25519SeedBin<'a> {
    type Target = Buffer<'a, buffer_type::Curve25519SeedBinType>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Curve25519SeedBin<'static> {
    #[allow(dead_code)]
    pub(crate) fn new(owned: Vec<u8>) -> Self {
        Self(Buffer::new(owned))
    }
    #[allow(dead_code)]
    pub(crate) fn take_from_slice(owned: &mut [u8]) -> Self {
        Self(Buffer::take_from_slice(owned))
    }
}

impl Debug for Curve25519SeedBin<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.debug_struct(stringify!(Curve25519SeedBin)).finish()
    }
}

impl<'a> From<Buffer<'a, buffer_type::Curve25519SeedBinType>> for Curve25519SeedBin<'a> {
    fn from(value: Buffer<'a, buffer_type::Curve25519SeedBinType>) -> Self {
        Self(value)
    }
}

/// Trait for values that can be serialized into a big-endian format
pub trait AsBigEndian<T> {
    /// Serializes into a big-endian format.
    ///
    /// # Errors
    /// Returns Unspecified if serialization fails.
    fn as_be_bytes(&self) -> Result<T, crate::error::Unspecified>;
}
