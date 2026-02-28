// Copyright (c) 2024 Intel
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

pub type Result<T> = std::result::Result<T, BlockDeviceError>;

#[derive(Error, Debug)]
pub enum BlockDeviceError {
    #[error("device_id must be in the format of `MAJ:MIN")]
    IllegalDeviceId,

    #[error("Either `device_id` or `device_path` must be specified")]
    NoDeviceSpecified,

    #[error("Failed to get device path with major: {major}, minor: {minor}")]
    NoDeviceFound { major: u32, minor: u32 },

    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Failed to serialize or deserialize JSON: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("The scheme of the key uri should be `kbs`, `file` or `sealed`")]
    IllegalKeyScheme,

    #[error("Failed to get key: {source}")]
    GetKeyFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("Error when doing luks2 operation: {source}")]
    Luks2Error {
        #[source]
        source: anyhow::Error,
    },

    #[error("Failed to umount device {mount_point}: {source}")]
    UmountFailed {
        mount_point: String,
        #[source]
        source: nix::Error,
    },

    #[error("Error when doing zfs operation: {source}")]
    ZfsError {
        #[source]
        source: anyhow::Error,
    },
}
