// Copyright (c) 2024 Intel
// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # BlockDevice SecureStorage

pub mod error;

use super::SecureMount;
use crate::{
    secret,
    storage::drivers::{
        filesystem::FsType,
        zfs::{
            create_zdataset, create_zpool, export_zpool, import_zpool, is_zfs_installed, load_key,
            mount_dataset, DEFAULT_ZDATASET_NAME, DEFAULT_ZPOOL_NAME,
        },
    },
};

use anyhow::anyhow;
use async_trait::async_trait;
use crypto::rand::random_bytes;
use error::{BlockDeviceError, Result};
use kms::{Annotations, ProviderSettings};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum::{Display, EnumString};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

#[derive(EnumString, Serialize, Deserialize, Display, Debug, PartialEq, Eq)]
#[serde(tag = "encryptionType")]
pub enum BlockDeviceEncryptType {
    #[cfg(feature = "luks2")]
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

    #[strum(serialize = "zfs")]
    #[serde(rename = "zfs")]
    Zfs {
        /// The name of the zpool to use.
        /// If not set, [`crate::storage::drivers::zfs::DEFAULT_ZPOOL_NAME`] will be used.
        pool: Option<String>,

        /// The name of the zdataset to use.
        /// If not set, [`crate::storage::drivers::zfs::DEFAULT_ZDATASET_NAME`] will be used.
        dataset: Option<String>,
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

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum SourceType {
    /// The source is an encrypted device.
    #[serde(rename = "encrypted")]
    Encrypted,

    /// The source is an empty device.
    #[serde(rename = "empty")]
    Empty,
}

/// The type of the target mount point.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(tag = "targetType")]
#[serde(rename_all = "camelCase")]
pub enum TargetType {
    /// The target is a device.
    Device,

    /// The target is a filesystem directory.
    FileSystem {
        /// The type of the target filesystem.
        /// In some cases, the filesystem type is determined by the higher
        /// level encryption_type ([`BlockDeviceEncryptType`]), so this
        /// field will be optional.
        #[serde(rename = "filesystemType")]
        #[serde(default)]
        filesystem_type: FsType,

        /// Extra options passed verbatim to mkfs.<fs> when it is needed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
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

    /// The type of the source.
    #[serde(rename = "sourceType")]
    pub source_type: SourceType,

    /// The type of the target mount point.
    #[serde(flatten)]
    pub target_type: TargetType,

    /// The key to encrypt or decrypt the device.
    ///
    /// If not set, generate a random 4096-byte key.
    ///
    /// Legal values are starting with:
    /// - "sealed.": Get the encryption key from the sealed secret.
    /// - "kbs://": Get the encryption key from the KBS.
    /// - "file://": Get the encryption key from the local file.
    pub key: Option<String>,

    /// The encryption type. Currently, only LUKS is supported.
    #[serde(flatten)]
    pub encryption_type: BlockDeviceEncryptType,
}

#[derive(Default)]
pub struct BlockDevice {
    /// Paths to remove on umount (e.g. symlinks created for device target, LUKS header files).
    temp_paths: Vec<String>,

    /// The mount points created by the operation. This is used to
    /// clean up.
    mount_points: Vec<String>,

    /// The cryptsetup pairs created by the operation. This is used to
    /// clean up.
    ///
    /// It is (device-path, dev-mapper-name)
    #[cfg(feature = "luks2")]
    cryptsetup_pairs: Vec<(String, String)>,

    /// The zfs pools created by the operation. This is used to
    /// clean up.
    zfs_pools: Vec<String>,
}

impl BlockDevice {
    /// The BlockDevice mount operation will be performed according to the parameters in the options.
    async fn real_mount(
        &mut self,
        options: &HashMap<String, String>,
        _flags: &[String],
        mount_point: &str,
    ) -> Result<()> {
        // construct BlockDeviceParameters
        let parameters = serde_json::to_string(options)?;
        let parameters: BlockDeviceParameters = serde_json::from_str(&parameters)?;

        // 1. get the source device path
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

        // 2. get key if the parameter is set
        let key = match &parameters.key {
            Some(key) => get_plaintext_key(key).await?,
            None => {
                debug!("generate a random key. All data on the device will be overwritten.");
                Zeroizing::new(random_bytes::<4096>())
            }
        };

        // 3. do the workflow according to the source type and target type according to different encryption types
        match parameters.encryption_type {
            #[cfg(feature = "luks2")]
            BlockDeviceEncryptType::Luks2 {
                data_integrity,
                mapper_name,
            } => {
                use crate::storage::drivers::{filesystem::FsFormatter, luks2::Luks2Formatter};
                use nix::mount::{mount, MsFlags};
                use tokio::fs::symlink;

                let integrity = data_integrity.map_or(false, |e| e.parse().unwrap_or(false));
                let formatter = Luks2Formatter::default().with_integrity(integrity);
                // 3.1 if the source type is empty, encrypt the device and create detached header
                let header_path = if parameters.source_type == SourceType::Empty {
                    warn!("encrypting the device. This will wipe original data on the disk.");
                    let header_path = luks2::luks_header_path(&device_path);
                    luks2::prepare_luks_header_file(&header_path)?;
                    self.temp_paths.push(header_path.clone());
                    formatter
                        .encrypt_device(&device_path, Some(&header_path), key.clone())
                        .map_err(|source| BlockDeviceError::Luks2Error { source })?;
                    Some(header_path)
                } else {
                    None
                };

                let devmapper_name = mapper_name.unwrap_or_else(|| {
                    debug!("No mapper name provided, generating a random one");
                    uuid::Uuid::new_v4().to_string()
                });

                debug!("luks2 opening device: {}", device_path);
                formatter
                    .open_device(&device_path, header_path.as_deref(), &devmapper_name, key)
                    .map_err(|source| BlockDeviceError::Luks2Error { source })?;

                let dev_path = format!("/dev/mapper/{}", devmapper_name);

                self.cryptsetup_pairs
                    .push((device_path.clone(), devmapper_name.clone()));

                match (parameters.target_type, parameters.source_type) {
                    // 3.2 if the target type is device, do the symlink operation to map
                    // the device path to the mount point.
                    (TargetType::Device, _) => {
                        info!(
                            "symlinking device: {} to mount point: {}",
                            dev_path, mount_point
                        );
                        symlink(&dev_path, mount_point).await.map_err(|source| {
                            BlockDeviceError::CreateSymlinkFailed {
                                source,
                                source_path: dev_path.to_string(),
                                target_path: mount_point.to_string(),
                            }
                        })?;

                        self.temp_paths.push(mount_point.to_string());
                        debug!("created symlink {} => {}", mount_point, dev_path);
                    }
                    // 3.3 if the source type is encrypted, meaning that there is
                    // already a filesystem on the device, so we just need to mount it to the mount point.
                    (
                        TargetType::FileSystem {
                            filesystem_type, ..
                        },
                        SourceType::Encrypted,
                    ) => {
                        info!(
                            "mounting device: {} to mount point: {}",
                            dev_path, mount_point
                        );
                        mount::<_, _, str, _>(
                            Some(&dev_path[..]),
                            mount_point,
                            Some(filesystem_type.as_ref()),
                            MsFlags::MS_NOATIME,
                            Some(""),
                        )
                        .map_err(|source| {
                            BlockDeviceError::MountFailed {
                                mount_point: mount_point.to_string(),
                                device: dev_path.to_string(),
                                source,
                            }
                        })?;

                        self.mount_points.push(mount_point.to_string());
                    }
                    // 3.4 if the source type is empty, meaning that we should also make
                    // a filesystem on the device.
                    (
                        TargetType::FileSystem {
                            filesystem_type,
                            mkfs_opts,
                        },
                        SourceType::Empty,
                    ) => {
                        info!(
                            "formatting device: {} and mounting it to mount point: {}",
                            dev_path, mount_point
                        );
                        let args = mkfs_opts
                            .map(|s| {
                                s.split_ascii_whitespace()
                                    .map(|x| x.to_string())
                                    .collect::<Vec<String>>()
                            })
                            .unwrap_or_default();
                        debug!(
                            device_path = dev_path,
                            filesystem_type = ?filesystem_type,
                            args = ?args,
                            "formatting device"
                        );
                        let fs_formatter = FsFormatter {
                            fs_type: filesystem_type,
                            force: true,
                            args: args,
                        };

                        fs_formatter
                            .format_integrity_compatible(&dev_path)
                            .map_err(|source| BlockDeviceError::MakeFileSystemFailed {
                                fs: filesystem_type,
                                device: dev_path.clone(),
                                source,
                            })?;

                        debug!("mounting device: {}", dev_path);
                        mount(
                            Some(&dev_path[..]),
                            mount_point,
                            Some(filesystem_type.as_ref()),
                            MsFlags::MS_NOATIME,
                            Some(""),
                        )
                        .map_err(|source| {
                            BlockDeviceError::MountFailed {
                                mount_point: mount_point.to_string(),
                                device: dev_path.to_string(),
                                source,
                            }
                        })?;

                        self.mount_points.push(mount_point.to_string());
                    }
                }
            }
            BlockDeviceEncryptType::Zfs { pool, dataset } => {
                if !is_zfs_installed() {
                    return Err(BlockDeviceError::ZfsError {
                        source: anyhow!("zfs is not installed. Please install zfsutils-linux and enable the zfs module in the kernel."),
                    });
                }
                let pool = pool.unwrap_or_else(|| {
                    warn!("No pool name provided, using default pool name");
                    DEFAULT_ZPOOL_NAME.to_string()
                });
                let dataset = dataset.unwrap_or_else(|| {
                    warn!("No dataset name provided, using default dataset name");
                    DEFAULT_ZDATASET_NAME.to_string()
                });

                if parameters.target_type == TargetType::Device {
                    return Err(BlockDeviceError::ZfsError {
                        source: anyhow!("zfs is not supported for device target type."),
                    });
                }

                // if the source type is empty, create a new zpool and zdataset
                if parameters.source_type == SourceType::Empty {
                    warn!("creating a new zpool and zdataset on the device. This will wipe original data on the disk.");
                    create_zpool(&pool, &device_path)
                        .map_err(|source| BlockDeviceError::ZfsError { source })?;
                    self.zfs_pools.push(pool.clone());
                    create_zdataset(&pool, &dataset, key.clone(), mount_point)
                        .map_err(|source| BlockDeviceError::ZfsError { source })?;
                } else {
                    // if the source type is encrypted, import the zpool and load the key to the zdataset
                    info!("importing the zpool and loading the key to the zdataset on the device.");
                    import_zpool(&pool, &device_path)
                        .map_err(|source| BlockDeviceError::ZfsError { source })?;
                    self.zfs_pools.push(pool.clone());
                    load_key(&pool, &dataset, key.clone())
                        .map_err(|source| BlockDeviceError::ZfsError { source })?;
                    mount_dataset(&pool, &dataset, Some(mount_point))
                        .map_err(|source| BlockDeviceError::ZfsError { source })?;
                }
            }
        }
        info!("Target path {} mounted successfully", mount_point);
        Ok(())
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

        // 2. remove temporary paths (symlinks, LUKS header files, etc.)
        for path in &self.temp_paths {
            tokio::fs::remove_file(path).await?;
        }

        // 3. close luks2 devices
        #[cfg(feature = "luks2")]
        for (_, name) in &self.cryptsetup_pairs {
            let formatter = crate::storage::drivers::luks2::Luks2Formatter::default();
            formatter
                .close_device(name)
                .map_err(|source| BlockDeviceError::Luks2Error { source })?;
        }

        // 4. export zfs pools. This will release the zpool from the current machine.
        for pool in &self.zfs_pools {
            export_zpool(pool).map_err(|source| BlockDeviceError::ZfsError { source })?;
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
        if let Some(line) = line.strip_prefix("DEVNAME=") {
            return Ok(format!("/dev/{}", line));
        }
    }
    Err(BlockDeviceError::NoDeviceFound { major, minor })
}

#[cfg(test)]
mod tests {
    use serial_test::serial;
    use tempfile::TempDir;
    use tracing::warn;

    use crate::storage::{
        drivers::{zfs::is_zfs_installed, TempFileLoopDevice},
        tests::init_tracing,
    };

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

    #[cfg(feature = "luks2")]
    #[tokio::test]
    #[rstest::rstest]
    #[serial]
    #[case::integrity("true")]
    #[case::no_integrity("false")]
    async fn encrypt_an_empty_device_and_make_a_filesystem_on_it_using_luks2(
        #[case] integrity: &str,
    ) {
        use std::io::Write;
        let mut temp_device_file = tempfile::NamedTempFile::new().unwrap();
        temp_device_file
            .as_file_mut()
            .write_all(&vec![0; 512 * 1024 * 1024])
            .unwrap();
        let mut bd = BlockDevice::default();
        let device_path = temp_device_file.path().to_string_lossy().to_string();

        let options = HashMap::from([
            ("sourceType".to_string(), "empty".to_string()),
            ("targetType".to_string(), "fileSystem".to_string()),
            ("devicePath".to_string(), device_path.clone()),
            ("encryptionType".to_string(), "luks2".to_string()),
            (
                "key".to_string(),
                "file://./test_files/luks2-disk-passphrase".to_string(),
            ),
            ("dataIntegrity".to_string(), integrity.to_string()),
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
    }

    #[cfg(feature = "luks2")]
    #[tokio::test]
    #[rstest]
    #[serial]
    #[case::integrity("true")]
    #[case::no_integrity("false")]
    async fn encrypt_an_empty_device_with_mkfs_opts_using_luks2(#[case] integrity: &str) {
        let mut temp_device_file = tempfile::NamedTempFile::new().unwrap();
        temp_device_file
            .as_file_mut()
            .write_all(&vec![0; 512 * 1024 * 1024])
            .unwrap();
        let mut bd = BlockDevice::default();
        let device_path = temp_device_file.path().to_string_lossy().to_string();

        let options = HashMap::from([
            ("sourceType".to_string(), "empty".to_string()),
            ("targetType".to_string(), "fileSystem".to_string()),
            ("devicePath".to_string(), device_path.clone()),
            ("encryptionType".to_string(), "luks2".to_string()),
            (
                "key".to_string(),
                "file://./test_files/luks2-disk-passphrase".to_string(),
            ),
            ("dataIntegrity".to_string(), integrity.to_string()),
            ("filesystemType".to_string(), "ext4".to_string()),
            (
                "mkfsOpts".to_string(),
                "-O ^has_journal -m 0 -i 163840 -I 128".to_string(),
            ),
        ]);

        let tempdir = tempfile::TempDir::new().unwrap();
        bd.real_mount(&options, &[], tempdir.path().to_str().unwrap())
            .await
            .unwrap();

        tokio::fs::write(tempdir.path().join("test-file"), b"some data")
            .await
            .unwrap();

        bd.umount().await.unwrap();
    }

    #[cfg(feature = "luks2")]
    #[tokio::test]
    #[serial]
    async fn encrypt_an_empty_device_using_luks2() {
        use rand::{distr::Alphanumeric, rng, Rng};
        use std::io::Write;
        use std::path::Path;

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
            ("sourceType".to_string(), "empty".to_string()),
            ("targetType".to_string(), "device".to_string()),
            ("devicePath".to_string(), device_path.clone()),
            ("encryptionType".to_string(), "luks2".to_string()),
            ("dataIntegrity".to_string(), "false".to_string()),
            (
                "key".to_string(),
                "file://./test_files/luks2-disk-passphrase".to_string(),
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

    #[cfg(feature = "luks2")]
    #[tokio::test]
    #[serial]
    async fn open_pre_encrypted_device_using_luks2_with_key() {
        use crate::storage::drivers::luks2::Luks2Formatter;
        use zeroize::Zeroizing;

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
        let device_path = temp_device_file.path().to_string_lossy().to_string();

        let passphrase =
            Zeroizing::new(std::fs::read("./test_files/luks2-disk-passphrase").unwrap());
        let formatter = Luks2Formatter { integrity: false };
        formatter
            .encrypt_device(&device_path, None, passphrase)
            .unwrap();

        let mut bd = BlockDevice::default();
        let options = HashMap::from([
            ("sourceType".to_string(), "encrypted".to_string()),
            ("targetType".to_string(), "device".to_string()),
            ("devicePath".to_string(), device_path),
            ("encryptionType".to_string(), "luks2".to_string()),
            ("dataIntegrity".to_string(), "false".to_string()),
            (
                "key".to_string(),
                "file://./test_files/luks2-disk-passphrase".to_string(),
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

    #[cfg(feature = "luks2")]
    #[tokio::test]
    #[serial]
    async fn encrypt_empty_device_without_key_uses_random_key() {
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
            ("sourceType".to_string(), "empty".to_string()),
            ("targetType".to_string(), "device".to_string()),
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
    async fn encrypt_an_empty_device_using_zfs() {
        init_tracing();
        if !is_zfs_installed() {
            warn!("zfs is not installed. Skipping zfs flow test.");
            return;
        }

        let pool_name = "pool1";
        let dataset_name = "dataset1";

        let mut bd = BlockDevice::default();
        let temp_device = TempFileLoopDevice::new(200 * 1024 * 1024).unwrap();
        let device_path = temp_device.dev_path();
        let options = HashMap::from([
            ("sourceType".to_string(), "empty".to_string()),
            ("devicePath".to_string(), device_path.to_string()),
            ("encryptionType".to_string(), "zfs".to_string()),
            (
                "key".to_string(),
                "file://./test_files/zfs-disk-passphrase".to_string(),
            ),
            ("pool".to_string(), pool_name.to_string()),
            ("dataset".to_string(), dataset_name.to_string()),
        ]);

        let mount_point = TempDir::new().unwrap();
        let mount_point_path = mount_point.path().to_str().unwrap();
        bd.real_mount(&options, &[], mount_point_path)
            .await
            .unwrap();
        // Try to write a file in the directory
        tokio::fs::write(mount_point.path().join("test-file"), b"some data")
            .await
            .unwrap();

        bd.umount().await.unwrap();

        let mut bd = BlockDevice::default();
        let options = HashMap::from([
            ("sourceType".to_string(), "encrypted".to_string()),
            ("targetType".to_string(), "fileSystem".to_string()),
            ("devicePath".to_string(), device_path.to_string()),
            ("encryptionType".to_string(), "zfs".to_string()),
            (
                "key".to_string(),
                "file://./test_files/zfs-disk-passphrase".to_string(),
            ),
            ("pool".to_string(), pool_name.to_string()),
            ("dataset".to_string(), dataset_name.to_string()),
        ]);
        bd.real_mount(&options, &[], mount_point_path)
            .await
            .unwrap();
        assert!(mount_point.path().join("test-file").exists());
        let content = tokio::fs::read_to_string(mount_point.path().join("test-file"))
            .await
            .unwrap();
        assert_eq!(content, "some data");
        bd.umount().await.unwrap();
    }
}
