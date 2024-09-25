// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#![allow(clippy::doc_markdown)]
//! A [*ring*](https://github.com/briansmith/ring)-compatible crypto library using the cryptographic
//! operations provided by [*AWS-LC*](https://github.com/aws/aws-lc). It uses either the
//! auto-generated [*aws-lc-sys*](https://crates.io/crates/aws-lc-sys) or
//! [*aws-lc-fips-sys*](https://crates.io/crates/aws-lc-fips-sys)
//! Foreign Function Interface (FFI) crates found in this repository for invoking *AWS-LC*.
//!
//! # Build
//!
//! `aws-lc-rs` is available through [crates.io](https://crates.io/crates/aws-lc-rs). It can
//! be added to your project in the [standard way](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
//! using `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! aws-lc-rs = "1.0.0"
//! ```
//!
//! Consuming projects will need a C Compiler (Clang or GCC) to build.
//! For some platforms, the build may also require CMake.
//! Building with the "fips" feature on any platform requires **CMake** and **Go**.
//!
//! See our [User Guide](https://aws.github.io/aws-lc-rs/) for guidance on installing build requirements.
//!
//! # Feature Flags
//!
//! #### alloc (default)
//!
//! Allows implementation to allocate values of arbitrary size. (The meaning of this feature differs
//! from the "alloc" feature of *ring*.) Currently, this is required by the `io::writer` module.
//!
//! #### ring-io (default)
//!
//! Enable feature to access the  `io`  module.
//!
//! #### ring-sig-verify (default)
//!
//! Enable feature to preserve compatibility with ring's `signature::VerificationAlgorithm::verify`
//! function. This adds a requirement on `untrusted = "0.7.1"`.
//!
//! #### fips
//!
//! Enable this feature to have aws-lc-rs use the [*aws-lc-fips-sys*](https://crates.io/crates/aws-lc-fips-sys)
//! crate for the cryptographic implementations. The *aws-lc-fips-sys* crate provides bindings to
//! [AWS-LC-FIPS 2.x](https://github.com/aws/aws-lc/tree/fips-2022-11-02), which has completed
//! FIPS validation testing by an accredited lab and has been submitted to NIST for certification.
//! The static build of AWS-LC-FIPS is used.
//!
//! Refer to the
//! [NIST Cryptographic Module Validation Program's Modules In Progress List](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/Modules-In-Process-List)
//! for the latest status of the static or dynamic AWS-LC Cryptographic Module. A complete list of supported operating
//! environments will be made available in the vendor security policy once the validation certificate has been issued. We
//! will also update our release notes
//! and documentation to reflect any changes in FIPS certification status.
//!
//! #### asan
//!
//! Performs an "address sanitizer" build. This can be used to help detect memory leaks. See the
//! ["Address Sanitizer" section](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html#addresssanitizer)
//! of the [Rust Unstable Book](https://doc.rust-lang.org/beta/unstable-book/).
//!
//! #### bindgen
//!
//! Causes `aws-lc-sys` or `aws-lc-fips-sys` to generates fresh bindings for AWS-LC instead of using
//! the pre-generated bindings. This feature requires `libclang` to be installed. See the
//! [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html)
//! for [rust-bindgen](https://github.com/rust-lang/rust-bindgen)
//!
//! #### prebuilt-nasm
//!
//! Enables the use of crate provided prebuilt NASM objects under certain conditions. This only affects builds for
//! Windows x86-64 platforms. This feature is ignored if the "fips" feature is also enabled.
//!
//! Use of prebuilt NASM objects is prevented if either of the following conditions are true:
//! * The NASM assembler is detected in the build environment
//! * `AWS_LC_SYS_PREBUILT_NASM` environment variable is set with a value of `0`
//!
//! Be aware that [features are additive](https://doc.rust-lang.org/cargo/reference/features.html#feature-unification);
//! by enabling this feature, it is enabled for all crates within the same build.
//!
//! # Use of prebuilt NASM objects
//!
//! For Windows x86 and x86-64, NASM is required for assembly code compilation. On these platforms,
//! we recommend that you install [the NASM assembler](https://www.nasm.us/). If NASM is
//! detected in the build environment *it is used* to compile the assembly files. However,
//! if a NASM assembler is not available, and the "fips" feature is not enabled, then the build fails unless one of the following conditions are true:
//!
//! * You are building for `x86-64` and either:
//!    * The `AWS_LC_SYS_PREBUILT_NASM` environment variable is found and has a value of "1"; OR
//!    * `AWS_LC_SYS_PREBUILT_NASM` is *not found* in the environment AND the "prebuilt-nasm" feature has been enabled.
//!
//! If the above cases apply, then the crate provided prebuilt NASM objects will be used for the build. To prevent usage of prebuilt NASM
//! objects, install NASM in the build environment and/or set the variable `AWS_LC_SYS_PREBUILT_NASM` to `0` in the build environment to prevent their use.
//!
//! ## About prebuilt NASM objects
//!
//! Prebuilt NASM objects are generated using automation similar to the crate provided pregenerated bindings. See the repositories
//! [GitHub workflow configuration](https://github.com/aws/aws-lc-rs/blob/main/.github/workflows/sys-bindings-generator.yml) for more information.
//! The prebuilt NASM objects are checked into the repository
//! and are [available for inspection](https://github.com/aws/aws-lc-rs/tree/main/aws-lc-sys/builder/prebuilt-nasm).
//! For each PR submitted,
//! [CI verifies](https://github.com/aws/aws-lc-rs/blob/8fb6869fc7bde92529a5cca40cf79513820984f7/.github/workflows/tests.yml#L209-L241)
//! that the NASM objects newly built from source match the NASM objects currently in the repository.
//!
//! # *ring*-compatibility
//!
//! Although this library attempts to be fully compatible with *ring* (v0.16.x), there are a few places where our
//! behavior is observably different.
//!
//! * Our implementation requires the `std` library. We currently do not support a
//!   [`#![no_std]`](https://docs.rust-embedded.org/book/intro/no-std.html) build.
//! * We can only support a subset of the platforms supported by `aws-lc-sys`. See the list of
//!   supported platforms above.
//! * `Ed25519KeyPair::from_pkcs8` and `Ed25519KeyPair::from_pkcs8_maybe_unchecked` both support
//!   parsing of v1 or v2 PKCS#8 documents. If a v2 encoded key is provided to either function,
//!   public key component, if present, will be verified to match the one derived from the encoded
//!   private key.
//!
//! # Motivation
//!
//! Rust developers increasingly need to deploy applications that meet US and Canadian government
//! cryptographic requirements. We evaluated how to deliver FIPS validated cryptography in idiomatic
//! and performant Rust, built around our AWS-LC offering. We found that the popular ring (v0.16)
//! library fulfilled much of the cryptographic needs in the Rust community, but it did not meet the
//! needs of developers with FIPS requirements. Our intention is to contribute a drop-in replacement
//! for ring that provides FIPS support and is compatible with the ring API. Rust developers with
//! prescribed cryptographic requirements can seamlessly integrate aws-lc-rs into their applications
//! and deploy them into AWS Regions.
#![no_std]
#![warn(clippy::exhaustive_enums)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

#[cfg(any(test, rustyguard_unsafe_logging))]
extern crate std;

extern crate alloc;
extern crate aws_lc_sys as aws_lc;

pub mod aead;
pub mod agreement;
pub mod error;

mod rand;
mod buffer;
mod cbs;
mod cipher;
mod debug;
pub mod encoding;
mod evp_pkey;
mod hex;
mod iv;
mod ptr;

pub mod test;
