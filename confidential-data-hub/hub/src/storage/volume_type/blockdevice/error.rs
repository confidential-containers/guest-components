// Copyright (c) 2024 Intel
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

use crate::storage::drivers::filesystem::FsType;

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

    #[error("Create symlink [{source_path}] -> [{target_path}] failed: {source}")]
    CreateSymlinkFailed {
        #[source]
        source: std::io::Error,
        source_path: String,
        target_path: String,
    },

    #[error("Failed to make filesystem {fs:?} of device {device}: {source}")]
    MakeFileSystemFailed {
        fs: FsType,
        device: String,
        #[source]
        source: anyhow::Error,
    },

    #[error("Failed to mount device {device} to mount point {mount_point}: {source}")]
    MountFailed {
        mount_point: String,
        device: String,
        #[source]
        source: nix::Error,
    },

    #[error("Failed to umount device {mount_point}: {source}")]
    UmountFailed {
        mount_point: String,
        #[source]
        source: nix::Error,
    },

    #[error("No encryption feature is supported. Please enable feature\n1. 'luks2' to use LUKS2 encryption.")]
    NoEncryptionFeatureEnabled,
}
