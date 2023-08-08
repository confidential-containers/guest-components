// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a Aliyun KMS implementation.
//!
//! Aliyun KMS uses KMS from Alibaba Cloud to support all functions.
//! The product detail can be found here: <https://www.alibabacloud.com/product/kms>.

mod annotations;
mod client;
mod credential;

pub use client::AliyunKmsClient;
