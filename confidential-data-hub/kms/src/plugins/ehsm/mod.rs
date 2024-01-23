// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a eHSM KMS implementation.
//!
//! eHSM KMS uses eHSM-KMS to support all functions.
//! The project detail can be found here: <https://github.com/intel/ehsm>.

mod annotations;
mod client;
mod credential;

pub use client::EhsmKmsClient;
