// Copyright 2016 Brian Smith.
// Portions Copyright (c) 2016, Google Inc.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::aead::aead_ctx::AeadCtx;
use crate::error;

#[inline]
fn init_chacha_aead(key: &[u8], tag_len: usize) -> Result<AeadCtx, error::Unspecified> {
    AeadCtx::chacha20(key, tag_len)
}

use super::{Nonce, MAX_TAG_LEN, NONCE_LEN};
use super::{Tag, TAG_LEN};
use crate::error::Unspecified;
use crate::iv::FixedLength;
use aws_lc::{
    EVP_AEAD_CTX_open, EVP_AEAD_CTX_open_gather, EVP_AEAD_CTX_seal, EVP_AEAD_CTX_seal_scatter,
};
use core::fmt::Debug;
use core::{mem::MaybeUninit, ops::RangeFrom, ptr::null};

/// The maximum length of a nonce returned by our AEAD API.
const MAX_NONCE_LEN: usize = NONCE_LEN;

/// The maximum required tag buffer needed if using AWS-LC generated nonce construction
const MAX_TAG_NONCE_BUFFER_LEN: usize = MAX_TAG_LEN + MAX_NONCE_LEN;

/// An AEAD key without a designated role or nonce sequence.
pub struct ChaChaKey {
    ctx: AeadCtx,
}

#[allow(clippy::missing_fields_in_debug)]
impl Debug for ChaChaKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("ChaChaKey").finish()
    }
}

impl ChaChaKey {
    /// Constructs an `UnboundKey`.
    /// # Errors
    /// `error::Unspecified` if `key_bytes.len() != algorithm.key_len()`.
    pub fn new(key_bytes: &[u8]) -> Result<Self, Unspecified> {
        Ok(Self {
            ctx: init_chacha_aead(key_bytes, TAG_LEN)?,
        })
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

        self.open_combined(nonce, aad.as_ref(), &mut in_out[in_prefix_len..])?;

        // shift the plaintext to the left
        in_out.copy_within(in_prefix_len..in_prefix_len + ciphertext_len, 0);

        // `ciphertext_len` is also the plaintext length.
        Ok(&mut in_out[..ciphertext_len])
    }

    #[inline]
    pub(crate) fn open_separate_gather(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        in_ciphertext: &[u8],
        in_tag: &[u8],
        out_plaintext: &mut [u8],
    ) -> Result<(), Unspecified> {
        // ensure that the lengths match
        {
            let actual = in_ciphertext.len();
            let expected = out_plaintext.len();

            if actual != expected {
                return Err(Unspecified);
            }
        }

        unsafe {
            let aead_ctx = self.ctx.as_ref();
            let nonce = nonce.as_ref();

            if 1 != EVP_AEAD_CTX_open_gather(
                *aead_ctx.as_const(),
                out_plaintext.as_mut_ptr(),
                nonce.as_ptr(),
                nonce.len(),
                in_ciphertext.as_ptr(),
                in_ciphertext.len(),
                in_tag.as_ptr(),
                in_tag.len(),
                aad.as_ptr(),
                aad.len(),
            ) {
                return Err(Unspecified);
            }
            Ok(())
        }
    }

    #[inline]
    pub(crate) fn seal_in_place_append_tag<'a, InOut>(
        &self,
        nonce: Option<Nonce>,
        aad: &[u8],
        in_out: &'a mut InOut,
    ) -> Result<Nonce, Unspecified>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        match nonce {
            Some(nonce) => self.seal_combined(nonce, aad, in_out),
            None => self.seal_combined_randnonce(aad, in_out),
        }
    }

    #[inline]
    pub(crate) fn seal_in_place_separate_tag(
        &self,
        nonce: Option<Nonce>,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<(Nonce, Tag), Unspecified> {
        match nonce {
            Some(nonce) => self.seal_separate(nonce, aad, in_out),
            None => self.seal_separate_randnonce(aad, in_out),
        }
    }

    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn seal_in_place_separate_scatter(
        &self,
        nonce: Nonce,
        aad: &[u8],
        in_out: &mut [u8],
        extra_in: &[u8],
        extra_out_and_tag: &mut [u8],
    ) -> Result<(), Unspecified> {
        // ensure that the extra lengths match
        {
            let actual = extra_in.len() + TAG_LEN;
            let expected = extra_out_and_tag.len();

            if actual != expected {
                return Err(Unspecified);
            }
        }

        let nonce = nonce.as_ref();
        let mut out_tag_len = extra_out_and_tag.len();

        if 1 != unsafe {
            EVP_AEAD_CTX_seal_scatter(
                *self.ctx.as_ref().as_const(),
                in_out.as_mut_ptr(),
                extra_out_and_tag.as_mut_ptr(),
                &mut out_tag_len,
                extra_out_and_tag.len(),
                nonce.as_ptr(),
                nonce.len(),
                in_out.as_ptr(),
                in_out.len(),
                extra_in.as_ptr(),
                extra_in.len(),
                aad.as_ptr(),
                aad.len(),
            )
        } {
            return Err(Unspecified);
        }
        Ok(())
    }

    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    fn open_combined(
        &self,
        nonce: Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<(), Unspecified> {
        let nonce = nonce.as_ref();

        debug_assert_eq!(nonce.len(), NONCE_LEN);

        let plaintext_len = in_out.len() - TAG_LEN;

        let mut out_len = MaybeUninit::<usize>::uninit();
        if 1 != (unsafe {
            EVP_AEAD_CTX_open(
                *self.ctx.as_ref().as_const(),
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

        Ok(())
    }

    #[inline]
    fn seal_combined<InOut>(
        &self,
        nonce: Nonce,
        aad: &[u8],
        in_out: &mut InOut,
    ) -> Result<Nonce, Unspecified>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        let plaintext_len = in_out.as_mut().len();

        let alg_tag_len = TAG_LEN;

        debug_assert!(alg_tag_len <= MAX_TAG_LEN);

        let tag_buffer = [0u8; MAX_TAG_LEN];

        in_out.extend(tag_buffer[..alg_tag_len].iter());

        let mut out_len = MaybeUninit::<usize>::uninit();
        let mut_in_out = in_out.as_mut();

        {
            let nonce = nonce.as_ref();

            debug_assert_eq!(nonce.len(), NONCE_LEN);

            if 1 != (unsafe {
                EVP_AEAD_CTX_seal(
                    *self.ctx.as_ref().as_const(),
                    mut_in_out.as_mut_ptr(),
                    out_len.as_mut_ptr(),
                    plaintext_len + alg_tag_len,
                    nonce.as_ptr(),
                    nonce.len(),
                    mut_in_out.as_ptr(),
                    plaintext_len,
                    aad.as_ptr(),
                    aad.len(),
                )
            }) {
                return Err(Unspecified);
            }
        }

        Ok(nonce)
    }

    #[inline]
    fn seal_combined_randnonce<InOut>(
        &self,
        aad: &[u8],
        in_out: &mut InOut,
    ) -> Result<Nonce, Unspecified>
    where
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        let mut tag_buffer = [0u8; MAX_TAG_NONCE_BUFFER_LEN];

        let mut out_tag_len = MaybeUninit::<usize>::uninit();

        {
            let plaintext_len = in_out.as_mut().len();
            let in_out = in_out.as_mut();

            if 1 != (unsafe {
                EVP_AEAD_CTX_seal_scatter(
                    *self.ctx.as_ref().as_const(),
                    in_out.as_mut_ptr(),
                    tag_buffer.as_mut_ptr(),
                    out_tag_len.as_mut_ptr(),
                    tag_buffer.len(),
                    null(),
                    0,
                    in_out.as_ptr(),
                    plaintext_len,
                    null(),
                    0,
                    aad.as_ptr(),
                    aad.len(),
                )
            }) {
                return Err(Unspecified);
            }
        }

        let tag_len = TAG_LEN;
        let nonce_len = NONCE_LEN;

        let nonce = Nonce(FixedLength::<NONCE_LEN>::try_from(
            &tag_buffer[tag_len..tag_len + nonce_len],
        )?);

        in_out.extend(&tag_buffer[..tag_len]);

        Ok(nonce)
    }

    #[inline]
    fn seal_separate(
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
                    *self.ctx.as_ref().as_const(),
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

    #[inline]
    fn seal_separate_randnonce(
        &self,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<(Nonce, Tag), Unspecified> {
        let mut tag_buffer = [0u8; MAX_TAG_NONCE_BUFFER_LEN];

        debug_assert!(TAG_LEN + NONCE_LEN <= tag_buffer.len());

        let mut out_tag_len = MaybeUninit::<usize>::uninit();

        if 1 != (unsafe {
            EVP_AEAD_CTX_seal_scatter(
                *self.ctx.as_ref().as_const(),
                in_out.as_mut_ptr(),
                tag_buffer.as_mut_ptr(),
                out_tag_len.as_mut_ptr(),
                tag_buffer.len(),
                null(),
                0,
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

        let tag_len = TAG_LEN;
        let nonce_len = NONCE_LEN;

        let nonce = Nonce(FixedLength::<NONCE_LEN>::try_from(
            &tag_buffer[tag_len..tag_len + nonce_len],
        )?);

        let mut tag = [0u8; MAX_TAG_LEN];
        tag.copy_from_slice(&tag_buffer[..tag_len]);

        Ok((nonce, Tag(tag, tag_len)))
    }
}
