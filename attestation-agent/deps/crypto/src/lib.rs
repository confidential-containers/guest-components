// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # Crypto
//!
//! This crate encapsulates the basic crypto operations.
//!
//! ## Components
//!
//! This crate include the following public submodules:
//! - `symmetric`: Symmetric key en/decryption
//! - `teekey`: Asymmetric key pair used in KBS Attestation Protocol

mod native;

mod symmetric;
pub use symmetric::*;

mod asymmetric;
pub use asymmetric::*;

pub mod rand;
