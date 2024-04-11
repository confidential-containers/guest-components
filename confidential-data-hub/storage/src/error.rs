// Copyright (c) 2023 Intel
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

use crate::volume_type;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[cfg(feature = "aliyun")]
    #[error("Error when mounting Aliyun OSS")]
    AliyunOssError(#[from] volume_type::alibaba_cloud_oss::error::Error),

    #[error("Failed to recognize the storage type")]
    StorageTypeNotRecognized(#[from] strum::ParseError),
}
