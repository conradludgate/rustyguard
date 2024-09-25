// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
// Modifications copyright Conrad Ludgate. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![no_std]
#![allow(clippy::doc_markdown)]
#![warn(clippy::exhaustive_enums)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

#[cfg(any(test, rustyguard_unsafe_logging))]
extern crate std;

extern crate alloc;
extern crate aws_lc_sys as aws_lc;

pub mod aead;
pub mod agreement;
pub mod error;

mod debug;
mod evp_pkey;
mod hex;
mod ptr;

pub mod test;
