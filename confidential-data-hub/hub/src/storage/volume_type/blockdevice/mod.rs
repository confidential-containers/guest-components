// Copyright (c) 2024 Intel
// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # BlockDevice SecureStorage
//!
//! See [`Action`] for supported actions.

pub mod error;

use super::SecureMount;
use crate::{
    secret,
    storage::drivers::{
        filesystem::{FsFormatter, FsType},
        luks2::Luks2Formatter,
    },
};
use async_trait::async_trait;
use crypto::rand::random_bytes;
use error::{BlockDeviceError, Result};
use kms::{Annotations, ProviderSettings};
use log::{debug, warn};
use nix::mount::{mount, MsFlags};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum::{Display, EnumString};
use tokio::{
    fs::{symlink, File},
    io::{AsyncBufReadExt, BufReader},
};
use zeroize::Zeroizing;

#[derive(EnumString, Serialize, Deserialize, Display, Debug, PartialEq, Eq)]
#[serde(tag = "encryptionType")]
pub enum BlockDeviceEncryptType {
    #[strum(serialize = "luks2")]
    #[serde(rename = "luks2")]
    Luks2 {
        /// Indicates whether to enable dm-integrity.
        #[serde(rename = "dataIntegrity")]
        data_integrity: Option<String>,

        /// Optional name for /dev/mapper/<name>
        #[serde(rename = "mapperName")]
        mapper_name: Option<String>,
    },
}

async fn get_plaintext_key(key_uri: &str) -> Result<Zeroizing<Vec<u8>>> {
    let key = if key_uri.starts_with("sealed.") {
        debug!("get key with sealed secret");
        secret::unseal_secret(key_uri.as_bytes())
            .await
            .map_err(|source| BlockDeviceError::GetKeyFailed {
                source: source.into(),
            })?
    } else if key_uri.starts_with("kbs://") {
        debug!("get key from kbs");
        kms::new_getter("kbs", ProviderSettings::default())
            .await
            .map_err(|source| BlockDeviceError::GetKeyFailed {
                source: source.into(),
            })?
            .get_secret(key_uri, &Annotations::default())
            .await
            .map_err(|source| BlockDeviceError::GetKeyFailed {
                source: source.into(),
            })?
    } else if key_uri.starts_with("file://") {
        debug!("get key from local path");
        let path = key_uri.trim_start_matches("file://");
        tokio::fs::read(path).await?
    } else {
        return Err(BlockDeviceError::IllegalKeyScheme);
    };

    Ok(Zeroizing::new(key))
}

/// High-level action the blockdevice module performs.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "action")]
pub enum Action {
    /// Open an existing encrypted container and expose the cleartext
    /// device via `/dev/mapper/<name>`.
    DecryptMap {
        /// Decryption key of the block device.
        ///
        /// Legal values are starting with:
        /// - "sealed.": Get the encryption key from the sealed secret.
        /// - "kbs://": Get the encryption key from the KBS.
        /// - "file://": Get the encryption key from the local file.
        #[serde(rename = "decryptionKey")]
        decryption_key: String,
    },

    /// Wipe the device, encrypted it, and expose the cleartext mapper.
    EncryptMap {
        /// Encryption key of the block device.
        ///
        /// If not set, generate a random 4096-byte key.
        ///
        /// Legal values are starting with:
        /// - "sealed.": Get the encryption key from the sealed secret.
        /// - "kbs://": Get the encryption key from the KBS.
        /// - "file://": Get the encryption key from the local file.
        #[serde(rename = "encryptionKey")]
        encryption_key: Option<String>,
    },

    /// Open an existing LUKS2 volume, map **and** mount an existing file-system.
    DecryptMount {
        /// Decryption key of the block device.
        ///
        /// Legal values are starting with:
        /// - "sealed.": Get the encryption key from the sealed secret.
        /// - "kbs://": Get the encryption key from the KBS.
        /// - "file://": Get the encryption key from the local file.
        #[serde(rename = "decryptionKey")]
        decryption_key: String,

        /// File-system type.
        #[serde(rename = "filesystemType")]
        filesystem_type: FsType,
    },

    /// Wipe the device, encrypt it, create a fresh file system,
    /// and mount it.
    EncryptFormatMount {
        /// Decryption key of the block device.
        ///
        /// If not set, generate a random 4096-byte key.
        ///
        /// Legal values are starting with:
        /// - "sealed.": Get the encryption key from the sealed secret.
        /// - "kbs://": Get the encryption key from the KBS.
        /// - "file://": Get the encryption key from the local file.
        #[serde(rename = "encryptionKey")]
        encryption_key: Option<String>,

        /// File-system type.
        #[serde(rename = "filesystemType")]
        filesystem_type: FsType,

        /// Extra options passed verbatim to mkfs.<fs>
        #[serde(rename = "mkfsOpts")]
        mkfs_opts: Option<String>,
    },
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct BlockDeviceParameters {
    /// The device number, formatted as "MAJ:MIN".
    /// This is used to identify the block device.
    ///
    /// At least one of `device_id` or `device_path` must be set.
    /// If both are set, `device_id` will be used.
    #[serde(rename = "deviceId")]
    pub device_id: Option<String>,

    /// The path of the source device path. The data of
    /// the device will be encrypted.
    ///
    /// At least one of `device_id` or `device_path` must be set.
    /// If both are set, `device_id` will be used.
    #[serde(rename = "devicePath")]
    pub device_path: Option<String>,

    /// See [`Action`] for semantics.
    #[serde(flatten)]
    pub action: Action,

    /// The encryption type. Currently, only LUKS is supported.
    #[serde(flatten)]
    pub encryption_type: BlockDeviceEncryptType,
}

#[derive(Default)]
pub struct BlockDevice {
    /// The symbolic file created by the operation. This is used to
    /// clean up.
    symlink_names: Vec<String>,

    /// The mount points created by the operation. This is used to
    /// clean up.
    mount_points: Vec<String>,

    /// The cryptsetup pairs created by the operation. This is used to
    /// clean up.
    ///
    /// It is (device-path, dev-mapper-name)
    cryptsetup_pairs: Vec<(String, String)>,
}

impl BlockDevice {
    /// `mount_point` parameter behavior is determined by [`Action`] in `options`:
    ///
    /// 1. Map actions: symlink to device
    /// 2. Mount actions: mount point
    async fn real_mount(
        &mut self,
        options: &HashMap<String, String>,
        _flags: &[String],
        mount_point: &str,
    ) -> Result<()> {
        // construct BlockDeviceParameters
        let parameters = serde_json::to_string(options)?;
        let parameters: BlockDeviceParameters = serde_json::from_str(&parameters)?;

        // 1. get the device path
        let device_path = match (parameters.device_id, parameters.device_path) {
            (Some(device_id), _) => {
                let (maj, min) = parse_device_id(&device_id)?;
                get_device_path(maj, min).await?
            }
            (_, Some(device_path)) => device_path,
            _ => {
                return Err(BlockDeviceError::NoDeviceSpecified);
            }
        };

        // 2. get key
        let key = match &parameters.action {
            Action::DecryptMap { decryption_key, .. } => get_plaintext_key(&decryption_key).await?,
            Action::EncryptMap { encryption_key, .. } => match encryption_key {
                Some(key) => get_plaintext_key(&key).await?,
                None => {
                    debug!("generate a random key. All data on the device will be overwritten.");
                    Zeroizing::new(random_bytes::<4096>())
                }
            },
            Action::DecryptMount { decryption_key, .. } => {
                get_plaintext_key(&decryption_key).await?
            }
            Action::EncryptFormatMount { encryption_key, .. } => match encryption_key {
                Some(key) => get_plaintext_key(&key).await?,
                None => {
                    debug!("generate a random key. All data on the device will be overwritten.");
                    Zeroizing::new(random_bytes::<4096>())
                }
            },
        };

        // 3. open the block device
        let dev_path: String = match parameters.encryption_type {
            BlockDeviceEncryptType::Luks2 {
                data_integrity,
                mapper_name,
            } => {
                use uuid::Uuid;

                let formatter = Luks2Formatter::default()
                    .with_integrity(data_integrity.map_or(false, |e| e.parse().unwrap_or(false)));

                match parameters.action {
                    Action::EncryptMap { .. } | Action::EncryptFormatMount { .. } => {
                        warn!("encrypting the device. This will wipe original data on the disk.");
                        formatter
                            .encrypt_device(&device_path, key.clone())
                            .map_err(|source| BlockDeviceError::Luks2Error { source })?;
                    }
                    _ => {}
                }

                let devmapper_name = mapper_name.unwrap_or_else(|| {
                    debug!("No mapper name provided, generating a random one");
                    Uuid::new_v4().to_string()
                });

                formatter
                    .open_device(&device_path, &devmapper_name, key)
                    .map_err(|source| BlockDeviceError::Luks2Error { source })?;

                let dev_path = format!("/dev/mapper/{}", devmapper_name);

                self.cryptsetup_pairs
                    .push((device_path.clone(), devmapper_name.clone()));
                dev_path
            }
        };

        match parameters.action {
            // 4. if the Action is `*Map`, make a symlink from the device path to the mount point.
            Action::DecryptMap { .. } | Action::EncryptMap { .. } => {
                symlink(&dev_path, mount_point).await.map_err(|source| {
                    BlockDeviceError::CreateSymlinkFailed {
                        source,
                        source_path: dev_path.to_string(),
                        target_path: mount_point.to_string(),
                    }
                })?;

                self.symlink_names.push(mount_point.to_string());
                debug!("created symlink {} => {}", mount_point, dev_path);
                return Ok(());
            }
            // or, the Action is `*Mount`
            Action::DecryptMount {
                filesystem_type, ..
            } => {
                mount::<_, _, str, _>(
                    Some(&dev_path[..]),
                    mount_point,
                    Some(filesystem_type.as_ref()),
                    MsFlags::MS_NOATIME,
                    Some(""),
                )
                .map_err(|source| BlockDeviceError::MountFailed {
                    mount_point: mount_point.to_string(),
                    device: dev_path.to_string(),
                    source,
                })?;

                self.mount_points.push(mount_point.to_string());

                Ok(())
            }
            Action::EncryptFormatMount {
                filesystem_type,
                mkfs_opts,
                ..
            } => {
                let args = mkfs_opts
                    .map(|s| {
                        s.split_ascii_whitespace()
                            .map(|x| x.to_string())
                            .collect::<Vec<String>>()
                    })
                    .unwrap_or_default();
                let fs_formatter = FsFormatter {
                    fs_type: filesystem_type,
                    force: true,
                    args: args,
                };

                fs_formatter.format(&dev_path).await.map_err(|source| {
                    BlockDeviceError::MakeFileSystemFailed {
                        fs: filesystem_type,
                        device: dev_path.clone(),
                        source,
                    }
                })?;

                mount(
                    Some(&dev_path[..]),
                    mount_point,
                    Some(filesystem_type.as_ref()),
                    MsFlags::MS_NOATIME,
                    Some(""),
                )
                .map_err(|source| BlockDeviceError::MountFailed {
                    mount_point: mount_point.to_string(),
                    device: dev_path.to_string(),
                    source,
                })?;

                self.mount_points.push(mount_point.to_string());

                Ok(())
            }
        }
    }

    /// Unmount the block device from the given `mount_point`.
    pub async fn umount(&mut self) -> Result<()> {
        // 1. unmount the mount points
        for mount_point in &self.mount_points {
            nix::mount::umount(&mount_point[..]).map_err(|source| {
                BlockDeviceError::UmountFailed {
                    mount_point: mount_point.to_string(),
                    source,
                }
            })?;
        }

        // 2. remove the symbolic files
        for symbol_file in &self.symlink_names {
            tokio::fs::remove_file(symbol_file).await?;
        }

        // 3. close luks2 devices
        for (device_path, name) in &self.cryptsetup_pairs {
            let formatter = Luks2Formatter::default();
            formatter
                .close_device(device_path, name)
                .map_err(|source| BlockDeviceError::Luks2Error { source })?;
        }

        Ok(())
    }
}

#[async_trait]
impl SecureMount for BlockDevice {
    /// Mount the block device to the given `mount_point``.
    ///
    /// If `options.encrypt_type` is set to `LUKS2`, the device will be formated as a LUKS-encrypted device.
    /// Then use cryptsetup open the device and mount it to `mount_point` as plaintext.
    ///
    /// This is a wrapper for inner function to convert error type.
    async fn mount(
        &mut self,
        options: &HashMap<String, String>,
        flags: &[String],
        mount_point: &str,
    ) -> super::Result<()> {
        self.real_mount(options, flags, mount_point)
            .await
            .map_err(|e| e.into())
    }
}

fn parse_device_id(device_id: &str) -> Result<(u32, u32)> {
    let parts: Vec<&str> = device_id.split(':').collect();
    if parts.len() != 2 {
        return Err(BlockDeviceError::IllegalDeviceId);
    }
    let major = parts[0]
        .parse::<u32>()
        .map_err(|_| BlockDeviceError::IllegalDeviceId)?;
    let minor = parts[1]
        .parse::<u32>()
        .map_err(|_| BlockDeviceError::IllegalDeviceId)?;
    Ok((major, minor))
}

async fn get_device_path(major: u32, minor: u32) -> Result<String> {
    let uevent_path = format!("/sys/dev/block/{}:{}/uevent", major, minor);
    let file = File::open(uevent_path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.starts_with("DEVNAME=") {
            return Ok(format!("/dev/{}", &line["DEVNAME=".len()..]));
        }
    }
    Err(BlockDeviceError::NoDeviceFound { major, minor })
}

#[cfg(test)]
mod tests {
    use std::{io::Write, path::Path};

    use rand::{distr::Alphanumeric, rng, Rng};
    use serial_test::serial;

    use super::*;

    #[test]
    fn test_parse_device_id() {
        assert_eq!(parse_device_id("8:0").unwrap(), (8, 0));
        assert!(parse_device_id("8").is_err());
        assert!(parse_device_id("8:0:1").is_err());
        assert!(parse_device_id("invalid").is_err());
    }

    #[tokio::test]
    async fn test_get_device_path() {
        // We are assuming that the device with major number 7 and minor number 0 exists.
        // which means the loop device `/dev/loop*`.
        let major = 7; // Example major number
        let minor = 0; // Example minor number
        let device_path = get_device_path(major, minor).await.expect("Failed to get device path of a loop device. This is either test error or the current environment does not have any loop devices.");

        assert!(device_path.starts_with("/dev/loop"));
        assert!(device_path.len() > 4); // "/dev/" is 4 characters long
    }

    #[tokio::test]
    #[serial]
    async fn test_encrypt_format_mount_and_decrypt_mount() {
        let mut temp_device_file = tempfile::NamedTempFile::new().unwrap();
        temp_device_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let mut bd = BlockDevice::default();
        let device_path = temp_device_file.path().to_string_lossy().to_string();

        let options = HashMap::from([
            ("action".to_string(), "encryptFormatMount".to_string()),
            ("devicePath".to_string(), device_path.clone()),
            ("encryptionType".to_string(), "luks2".to_string()),
            (
                "encryptionKey".to_string(),
                format!("file://{}", "./test_files/luks2-disk-passphrase"),
            ),
            ("dataIntegrity".to_string(), "false".to_string()),
            ("filesystemType".to_string(), "ext4".to_string()),
        ]);

        let tempdir = tempfile::TempDir::new().unwrap();
        bd.real_mount(&options, &[], tempdir.path().to_str().unwrap())
            .await
            .unwrap();

        // Try to write a file in the directory
        tokio::fs::write(tempdir.path().join("test-file"), b"some data")
            .await
            .unwrap();

        bd.umount().await.unwrap();
        drop(bd);

        // Then try open the device
        let tempdir = tempfile::TempDir::new().unwrap();
        let mut bd = BlockDevice::default();
        let options = HashMap::from([
            ("action".to_string(), "decryptMount".to_string()),
            ("devicePath".to_string(), device_path.clone()),
            ("encryptionType".to_string(), "luks2".to_string()),
            ("dataIntegrity".to_string(), "false".to_string()),
            (
                "decryptionKey".to_string(),
                format!("file://{}", "./test_files/luks2-disk-passphrase"),
            ),
            ("filesystemType".to_string(), "ext4".to_string()),
        ]);

        bd.real_mount(&options, &[], tempdir.path().to_str().unwrap())
            .await
            .unwrap();

        assert!(tempdir.path().join("test-file").exists());
        let content = tokio::fs::read_to_string(tempdir.path().join("test-file"))
            .await
            .unwrap();
        assert_eq!(content, "some data");

        bd.umount().await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_encrypt_map() {
        let target_device_name = format!(
            "/dev/{}",
            rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect::<String>()
        );
        let mut temp_device_file = tempfile::NamedTempFile::new().unwrap();
        temp_device_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let mut bd = BlockDevice::default();
        let device_path = temp_device_file.path().to_string_lossy().to_string();
        let options = HashMap::from([
            ("action".to_string(), "encryptMap".to_string()),
            ("devicePath".to_string(), device_path.clone()),
            ("encryptionType".to_string(), "luks2".to_string()),
            ("dataIntegrity".to_string(), "false".to_string()),
        ]);

        bd.real_mount(&options, &[], &target_device_name)
            .await
            .unwrap();

        if !Path::new(&target_device_name).exists() {
            panic!("target device not exist");
        }

        bd.umount().await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_decrypt_map() {
        let target_device_name = format!(
            "/dev/{}",
            rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect::<String>()
        );
        let mut bd = BlockDevice::default();
        let device_path = "./test_files/luks2-disk".to_string();
        let options = HashMap::from([
            ("action".to_string(), "decryptMap".to_string()),
            ("devicePath".to_string(), device_path.clone()),
            ("encryptionType".to_string(), "luks2".to_string()),
            ("dataIntegrity".to_string(), "false".to_string()),
            (
                "decryptionKey".to_string(),
                format!("file://{}", "./test_files/luks2-disk-passphrase"),
            ),
        ]);

        bd.real_mount(&options, &[], &target_device_name)
            .await
            .unwrap();

        if !Path::new(&target_device_name).exists() {
            panic!("target device not exist");
        }

        bd.umount().await.unwrap();
    }
}
