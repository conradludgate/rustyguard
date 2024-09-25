// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
// Modifications copyright Conrad Ludgate. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::ptr::LcPtr;
use aws_lc::{EVP_PKEY_CTX_new, EVP_PKEY_up_ref, EVP_PKEY, EVP_PKEY_CTX};
use core::ptr::null_mut;

impl LcPtr<EVP_PKEY> {
    #[allow(non_snake_case)]
    pub(crate) fn create_EVP_PKEY_CTX(&self) -> Result<LcPtr<EVP_PKEY_CTX>, ()> {
        // The only modification made by EVP_PKEY_CTX_new to `priv_key` is to increment its
        // refcount. The modification is made while holding a global lock:
        // https://github.com/aws/aws-lc/blob/61503f7fe72457e12d3446853a5452d175560c49/crypto/refcount_lock.c#L29
        LcPtr::new(unsafe { EVP_PKEY_CTX_new(*self.as_mut_unsafe(), null_mut()) })
    }
}

impl Clone for LcPtr<EVP_PKEY> {
    fn clone(&self) -> Self {
        // EVP_PKEY_up_ref increments the refcount while holding a global lock:
        // https://github.com/aws/aws-lc/blob/61503f7fe72457e12d3446853a5452d175560c49/crypto/refcount_lock.c#L29
        assert_eq!(
            1,
            unsafe { EVP_PKEY_up_ref(*self.as_mut_unsafe()) },
            "infallible AWS-LC function"
        );
        Self::new(unsafe { *self.as_mut_unsafe() }).expect("non-null AWS-LC EVP_PKEY pointer")
    }
}
