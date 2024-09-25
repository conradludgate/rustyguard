// Copyright 2016 Brian Smith.
// Portions Copyright (c) 2016, Google Inc.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::ptr::LcPtr;

use super::aead_ctx::build_context;
use super::{Nonce, MAX_TAG_LEN, NONCE_LEN};
use super::{Tag, TAG_LEN};
use crate::error::Unspecified;
use aws_lc::{
    EVP_AEAD_CTX_open, EVP_AEAD_CTX_seal_scatter, EVP_aead_xchacha20_poly1305, EVP_AEAD_CTX,
};
use core::fmt::Debug;
use core::{mem::MaybeUninit, ops::RangeFrom, ptr::null};

/// An AEAD key without a designated role or nonce sequence.
pub struct XChaChaKey {
    ctx: LcPtr<EVP_AEAD_CTX>,
}

unsafe impl Send for XChaChaKey {}
unsafe impl Sync for XChaChaKey {}

#[allow(clippy::missing_fields_in_debug)]
impl Debug for XChaChaKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("XChaChaKey").finish()
    }
}

impl XChaChaKey {
    /// Constructs an `ChaChaKey`.
    pub fn new(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        let ctx = build_context(EVP_aead_xchacha20_poly1305, key_bytes, TAG_LEN)?;

        Ok(Self { ctx })
    }

    #[inline]
    pub(crate) fn open_within<'in_out>(
        &self,
        nonce: Nonce,
        aad: &[u8],
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], Unspecified> {
        let in_prefix_len = ciphertext_and_tag.start;
        let ciphertext_and_tag_len = in_out.len().checked_sub(in_prefix_len).ok_or(Unspecified)?;
        let ciphertext_len = ciphertext_and_tag_len
            .checked_sub(TAG_LEN)
            .ok_or(Unspecified)?;

        let in_out: &mut [u8] = &mut in_out[in_prefix_len..];
        let nonce = nonce.as_ref();

        debug_assert_eq!(nonce.len(), NONCE_LEN);

        let plaintext_len = in_out.len() - TAG_LEN;

        let mut out_len = MaybeUninit::<usize>::uninit();
        if 1 != (unsafe {
            EVP_AEAD_CTX_open(
                *self.ctx.as_const(),
                in_out.as_mut_ptr(),
                out_len.as_mut_ptr(),
                plaintext_len,
                nonce.as_ptr(),
                nonce.len(),
                in_out.as_ptr(),
                plaintext_len + TAG_LEN,
                aad.as_ptr(),
                aad.len(),
            )
        }) {
            return Err(Unspecified);
        }

        // shift the plaintext to the left
        in_out.copy_within(in_prefix_len..in_prefix_len + ciphertext_len, 0);

        // `ciphertext_len` is also the plaintext length.
        Ok(&mut in_out[..ciphertext_len])
    }

    #[inline]
    pub(crate) fn seal_in_place_separate_tag(
        &self,
        nonce: Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<(Nonce, Tag), Unspecified> {
        let mut tag = [0u8; MAX_TAG_LEN];
        let mut out_tag_len = MaybeUninit::<usize>::uninit();
        {
            let nonce = nonce.as_ref();

            debug_assert_eq!(nonce.len(), NONCE_LEN);

            if 1 != (unsafe {
                EVP_AEAD_CTX_seal_scatter(
                    *self.ctx.as_const(),
                    in_out.as_mut_ptr(),
                    tag.as_mut_ptr(),
                    out_tag_len.as_mut_ptr(),
                    tag.len(),
                    nonce.as_ptr(),
                    nonce.len(),
                    in_out.as_ptr(),
                    in_out.len(),
                    null(),
                    0usize,
                    aad.as_ptr(),
                    aad.len(),
                )
            }) {
                return Err(Unspecified);
            }
        }
        Ok((nonce, Tag(tag, unsafe { out_tag_len.assume_init() })))
    }
}
