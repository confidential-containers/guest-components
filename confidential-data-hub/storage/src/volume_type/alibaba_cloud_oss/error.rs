// Copyright (c) 2024 Intel
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error when getting plaintext of OSS parameters")]
    GetPlaintextParameter(#[from] anyhow::Error),

    #[error("Gocryptfs decryption mount failed")]
    GocryptfsMountFailed,

    #[error("I/O error")]
    IOError(#[from] std::io::Error),

    #[error("Failed to mount oss")]
    OssfsMountFailed,

    #[error("Serialize/Deserialize failed")]
    SerdeError(#[from] serde_json::Error),

    #[error("Failed to recognize the storage type")]
    StorageTypeNotRecognized(#[from] strum::ParseError),
}
