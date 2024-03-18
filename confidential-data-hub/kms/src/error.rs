// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use attestation_agent::config::aa_kbc_params;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[cfg(feature = "aliyun")]
    #[error("Aliyun KMS error: {0}")]
    AliyunKmsError(String),

    #[error("Attestation Agent client error: {0}")]
    AAClientError(String),

    #[cfg(feature = "resource_kbs")]
    #[error("Resource KBS client error: {0}")]
    ResourceKbsClientError(String),

    #[error("Kbs client error: {0}")]
    KbsClientError(String),

    #[cfg(feature = "ehsm")]
    #[error("eHSM-KMS client error: {0}")]
    EhsmKmsError(String),

    #[error("Unsupported provider: {0}")]
    UnsupportedProvider(String),

    #[error("aa_kbc_params error")]
    AaKbcParamsError(#[from] aa_kbc_params::ParamError),
}
