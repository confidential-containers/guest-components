// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[cfg(feature = "aliyun")]
    #[error("Aliyun KMS error: {0}")]
    AliyunKmsError(String),

    #[cfg(any(feature = "kbs", feature = "sev"))]
    #[error("Get kbs host failed: {0}")]
    GetKbsHost(String),

    #[cfg(feature = "kbs")]
    #[error("KBS Client error: {0}")]
    KbsClientError(String),

    #[cfg(feature = "sev")]
    #[error("Sev Client (online-sev-kbc) error: {0}")]
    SevClientError(String),

    #[error("Unsupported provider: {0}")]
    UnsupportedProvider(String),
}
