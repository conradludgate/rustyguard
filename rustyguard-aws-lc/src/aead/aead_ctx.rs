// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use core::mem::size_of;
use core::ptr::null_mut;

use crate::error::Unspecified;
use crate::ptr::LcPtr;
use aws_lc::{EVP_AEAD_CTX_init, EVP_AEAD_CTX_zero, OPENSSL_malloc, EVP_AEAD_CTX};

pub(crate) fn build_context(
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
