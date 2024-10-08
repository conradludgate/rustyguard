// Copyright 2016 Brian Smith.
// Portions Copyright (c) 2016, Google Inc.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
// Modifications copyright Conrad Ludgate. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::ptr::LcPtr;

use super::aead_ctx::build_context;
use super::{Tag, TAG_LEN};
use super::{XNonce, XNONCE_LEN};
use crate::error::Unspecified;
use aws_lc::{
    EVP_AEAD_CTX_open, EVP_AEAD_CTX_seal_scatter, EVP_aead_xchacha20_poly1305, EVP_AEAD_CTX,
};
use core::fmt::Debug;
use core::{mem::MaybeUninit, ptr::null};

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
        if 32 != key_bytes.len() {
            return Err(Unspecified);
        }
        let ctx = build_context(EVP_aead_xchacha20_poly1305, key_bytes, TAG_LEN)?;

        Ok(Self { ctx })
    }

    #[inline]
    pub(crate) fn open_in_place<'in_out>(
        &self,
        nonce: XNonce,
        aad: &[u8],
        in_out: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], Unspecified> {
        let ciphertext_and_tag_len = in_out.len();
        let ciphertext_len = ciphertext_and_tag_len
            .checked_sub(TAG_LEN)
            .ok_or(Unspecified)?;

        let nonce = nonce.as_ref();

        debug_assert_eq!(nonce.len(), XNONCE_LEN);

        let mut out_len = 0;
        if 1 != (unsafe {
            EVP_AEAD_CTX_open(
                *self.ctx.as_const(),
                in_out.as_mut_ptr(),
                &mut out_len,
                ciphertext_len,
                nonce.as_ptr(),
                nonce.len(),
                in_out.as_ptr(),
                ciphertext_len + TAG_LEN,
                aad.as_ptr(),
                aad.len(),
            )
        }) {
            return Err(Unspecified);
        }

        // `ciphertext_len` is also the plaintext length.
        Ok(&mut in_out[..ciphertext_len])
    }

    #[inline]
    pub(crate) fn seal_in_place_separate_tag(
        &self,
        nonce: XNonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<(XNonce, Tag), Unspecified> {
        let mut tag = [0u8; TAG_LEN];
        let mut out_tag_len = MaybeUninit::<usize>::uninit();
        {
            let nonce = nonce.as_ref();

            debug_assert_eq!(nonce.len(), XNONCE_LEN);

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

        unsafe { assert_eq!(out_tag_len.assume_init(), 16) }

        Ok((nonce, Tag(tag)))
    }
}
