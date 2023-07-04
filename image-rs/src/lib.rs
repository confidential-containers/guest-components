// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

/// Environment macro for `image-rs` work dir.
pub const CC_IMAGE_WORK_DIR: &str = "CC_IMAGE_WORK_DIR";

pub const ERR_BAD_UNCOMPRESSED_DIGEST: &str = "unsupported uncompressed digest format";

pub mod auth;
pub mod bundle;
pub mod config;
pub mod decoder;
pub mod decrypt;
pub mod digest;
pub mod image;
pub mod meta_store;
#[cfg(feature = "nydus")]
pub mod nydus;
pub mod pull;
pub mod resource;
#[cfg(feature = "signature")]
pub mod signature;
pub mod snapshots;
pub mod stream;
pub mod unpack;
