// Copyright (c) 2024 Intel
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

pub type Result<T> = std::result::Result<T, BlockDeviceError>;

#[derive(Error, Debug)]
pub enum BlockDeviceError {
    #[error("Error when getting encrypt/decrypt keys")]
    GetKeysFailure(#[from] anyhow::Error),

    #[error("LUKS decryption mount failed")]
    LUKSfsMountFailed,

    #[error("I/O error")]
    IOError(#[from] std::io::Error),

    #[error("Failed to mount block device")]
    BlockDeviceMountFailed,

    #[error("Serialize/Deserialize failed")]
    SerdeError(#[from] serde_json::Error),

    #[error("Failed to recognize the storage type")]
    StorageTypeNotRecognized(#[from] strum::ParseError),
}
