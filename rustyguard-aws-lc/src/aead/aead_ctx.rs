// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use core::mem::size_of;
use core::ptr::null_mut;

use crate::error::Unspecified;
use crate::ptr::LcPtr;
use aws_lc::{
    EVP_AEAD_CTX_init, EVP_AEAD_CTX_zero, EVP_aead_chacha20_poly1305, OPENSSL_malloc, EVP_AEAD_CTX,
};

#[allow(
    clippy::large_enum_variant,
    variant_size_differences,
    non_camel_case_types
)]
pub(crate) enum AeadCtx {
    CHACHA20_POLY1305(LcPtr<EVP_AEAD_CTX>),
}

unsafe impl Send for AeadCtx {}
unsafe impl Sync for AeadCtx {}

impl AeadCtx {
    pub(crate) fn chacha20(key_bytes: &[u8], tag_len: usize) -> Result<Self, Unspecified> {
        if 32 != key_bytes.len() {
            return Err(Unspecified);
        }
        Ok(AeadCtx::CHACHA20_POLY1305(AeadCtx::build_context(
            EVP_aead_chacha20_poly1305,
            key_bytes,
            tag_len,
        )?))
    }

    fn build_context(
        aead_fn: unsafe extern "C" fn() -> *const aws_lc::evp_aead_st,
        key_bytes: &[u8],
        tag_len: usize,
    ) -> Result<LcPtr<EVP_AEAD_CTX>, Unspecified> {
        let aead = unsafe { aead_fn() };

        // We are performing the allocation ourselves as EVP_AEAD_CTX_new will call EVP_AEAD_CTX_init by default
        // and this avoid having to zero and reinitalize again if we need to set an explicit direction.
        let mut aead_ctx: LcPtr<EVP_AEAD_CTX> =
            LcPtr::new(unsafe { OPENSSL_malloc(size_of::<EVP_AEAD_CTX>()) }.cast())?;

        unsafe { EVP_AEAD_CTX_zero(*aead_ctx.as_mut()) };

        if 1 != unsafe {
            EVP_AEAD_CTX_init(
                *aead_ctx.as_mut(),
                aead,
                key_bytes.as_ptr(),
                key_bytes.len(),
                tag_len,
                null_mut(),
            )
        } {
            return Err(Unspecified);
        }
        Ok(aead_ctx)
    }
}

impl AsRef<LcPtr<EVP_AEAD_CTX>> for AeadCtx {
    #[inline]
    fn as_ref(&self) -> &LcPtr<EVP_AEAD_CTX> {
        match self {
            AeadCtx::CHACHA20_POLY1305(ctx) => ctx,
        }
    }
}
