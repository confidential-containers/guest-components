// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # Crypto
//!
//! This crate encapsulates the basic crypto operations in both purely
//! rust and openssl (native). Features can be enabled to determine which
//! underlying implementation is used:
//! - `rust-crypto`: Use purely rust.
//! - `openssl`: Use openssl. If `rust-crypto` and `openssl` are both
//!   enabled, use `openssl`.
//!
//! ## Components
//!
//! This crate include the following public submodules:
//! - `symmetric`: Symmetric key en/decryption
//! - `teekey`: Asymmetric key pair used in KBS Attestation Protocol

#[macro_use]
extern crate strum;

#[cfg(feature = "openssl")]
mod native;
#[cfg(all(feature = "rust-crypto", not(feature = "openssl")))]
mod rust;

mod symmetric;
pub use symmetric::*;

mod asymmetric;
pub use asymmetric::*;
