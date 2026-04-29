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
    storage::drivers::zfs::{export_zpool, ZfsParameters},
};

use async_trait::async_trait;
use crypto::rand::random_bytes;
use error::{BlockDeviceError, Result};
use kms::{Annotations, ProviderSettings};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum::Display;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
};
use tracing::{debug, info};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize, Display, Debug, PartialEq, Eq)]
#[serde(tag = "encryptionType")]
pub enum BlockDeviceEncryptType {
    #[strum(serialize = "luks2")]
    #[serde(rename = "luks2")]
    Luks2(crate::storage::drivers::luks2::Luks2MountParameters),

    #[strum(serialize = "zfs")]
    #[serde(rename = "zfs")]
    Zfs(ZfsParameters),
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
            BlockDeviceEncryptType::Luks2(luks2_parameters) => {
                if luks2_parameters.target_type
                    == crate::storage::drivers::luks2::TargetType::Device
                {
                    self.temp_paths.push(mount_point.to_string());
                } else {
                    self.mount_points.push(mount_point.to_string());
                }
                luks2_parameters
                    .do_mount(&device_path, mount_point, key, parameters.source_type)
                    .await
                    .map_err(|source| BlockDeviceError::Luks2Error { source })?;
            }
            BlockDeviceEncryptType::Zfs(zfs_parameters) => {
                self.zfs_pools.push(zfs_parameters.pool.clone());
                zfs_parameters
                    .do_mount(&device_path, mount_point, key, parameters.source_type)
                    .await
                    .map_err(|source| BlockDeviceError::ZfsError { source })?;
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
    use std::path::Path;
    use tempfile::TempDir;
    use tracing::warn;

    use crate::storage::drivers::luks2::{luks_header_path, Luks2Formatter};
    use crate::storage::{
        drivers::{zfs::is_zfs_installed, TempFileLoopDevice},
        tests::init_tracing,
    };

    use super::*;

    const EXT4_INTEGRITY_MKFS_OPTS: &str = "-O ^has_journal -m 0 -i 163840 -I 128";

    struct Ext4StressConfig {
        workers: usize,
        data_files_per_worker: usize,
        tree_dirs_per_worker: usize,
    }

    const SINGLE_WORKER_EXT4_STRESS: Ext4StressConfig = Ext4StressConfig {
        workers: 1,
        data_files_per_worker: 128,
        tree_dirs_per_worker: 256,
    };

    const PARALLEL_EXT4_STRESS: Ext4StressConfig = Ext4StressConfig {
        workers: 16,
        data_files_per_worker: 128,
        tree_dirs_per_worker: 256,
    };

    fn close_luks_device(name: &str) {
        let path = format!("/dev/mapper/{name}");
        if Path::new(&path).exists() {
            let _ = Luks2Formatter::default().close_device(name);
        }
    }

    async fn close_luks_device_after_unmount(name: &str) {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        close_luks_device(name);
    }

    struct CloseDeviceOnDrop(String);

    impl Drop for CloseDeviceOnDrop {
        fn drop(&mut self) {
            close_luks_device(&self.0);
        }
    }

    struct RemoveFileOnDrop(String);

    impl Drop for RemoveFileOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn remove_luks_header_on_drop(device_path: &str) -> RemoveFileOnDrop {
        let header_path = luks_header_path(device_path);
        let _ = std::fs::remove_file(&header_path);
        RemoveFileOnDrop(header_path)
    }

    async fn run_ext4_stress(root: &Path, config: Ext4StressConfig) -> anyhow::Result<()> {
        let data = vec![0u8; 1024 * 1024];
        let mut tasks = Vec::with_capacity(config.workers);
        for worker in 0..config.workers {
            let worker_dir = root.join(format!("w{worker}"));
            let data = data.clone();
            let data_files_per_worker = config.data_files_per_worker;
            tasks.push(tokio::spawn(async move {
                tokio::fs::create_dir_all(&worker_dir).await?;
                for file in 0..data_files_per_worker {
                    tokio::fs::write(worker_dir.join(format!("f{file}")), &data).await?;
                }
                std::io::Result::Ok(())
            }));
        }

        let mut stress_error = None;
        for task in tasks {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    stress_error.get_or_insert_with(|| anyhow::Error::new(err));
                }
                Err(err) => {
                    stress_error.get_or_insert_with(|| anyhow::Error::new(err));
                }
            }
        }
        if let Some(err) = stress_error {
            return Err(err);
        }

        let mut tasks = Vec::with_capacity(config.workers);
        for worker in 0..config.workers {
            let worker_tree = root.join("trees").join(format!("w{worker}"));
            let tree_dirs_per_worker = config.tree_dirs_per_worker;
            tasks.push(tokio::spawn(async move {
                tokio::fs::create_dir_all(&worker_tree).await?;
                for dir in 0..tree_dirs_per_worker {
                    let dir_path = worker_tree.join(format!("d{dir}"));
                    tokio::fs::create_dir_all(&dir_path).await?;
                    tokio::fs::write(dir_path.join("file"), format!("w{worker}-{dir}")).await?;
                }
                std::io::Result::Ok(())
            }));
        }

        let mut stress_error = None;
        for task in tasks {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    stress_error.get_or_insert_with(|| anyhow::Error::new(err));
                }
                Err(err) => {
                    stress_error.get_or_insert_with(|| anyhow::Error::new(err));
                }
            }
        }
        if let Some(err) = stress_error {
            return Err(err);
        }

        Ok(())
    }

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

    #[rstest::rstest]
    #[case::integrity("true")]
    #[case::no_integrity("false")]
    #[tokio::test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    #[serial]
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

    #[rstest::rstest]
    #[case::integrity("true")]
    #[case::no_integrity("false")]
    #[tokio::test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    #[serial]
    async fn encrypt_an_empty_device_with_mkfs_opts_using_luks2(#[case] integrity: &str) {
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

    #[tokio::test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    #[serial]
    async fn encrypt_a_loop_device_with_integrity_and_mkfs_opts_using_luks2() {
        let temp_device = TempFileLoopDevice::new(512 * 1024 * 1024).unwrap();
        let device_path = temp_device.dev_path().to_string();
        let _header_guard = remove_luks_header_on_drop(&device_path);
        let mapper_name = format!("luks2-loop-integrity-test-{}", std::process::id());
        let _mapper_guard = CloseDeviceOnDrop(mapper_name.clone());
        let mut bd = BlockDevice::default();

        let options = HashMap::from([
            ("sourceType".to_string(), "empty".to_string()),
            ("targetType".to_string(), "fileSystem".to_string()),
            ("devicePath".to_string(), device_path),
            ("encryptionType".to_string(), "luks2".to_string()),
            (
                "key".to_string(),
                "file://./test_files/luks2-disk-passphrase".to_string(),
            ),
            ("mapperName".to_string(), mapper_name.clone()),
            ("dataIntegrity".to_string(), "true".to_string()),
            ("filesystemType".to_string(), "ext4".to_string()),
            ("mkfsOpts".to_string(), EXT4_INTEGRITY_MKFS_OPTS.to_string()),
        ]);

        let tempdir = TempDir::new().unwrap();
        let result = bd
            .real_mount(&options, &[], tempdir.path().to_str().unwrap())
            .await;
        if result.is_err() {
            close_luks_device(&mapper_name);
        }
        result.unwrap();

        tokio::fs::write(tempdir.path().join("test-file"), b"some data")
            .await
            .unwrap();

        bd.umount().await.unwrap();
        close_luks_device_after_unmount(&mapper_name).await;
    }

    #[tokio::test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    #[serial]
    async fn encrypt_a_loop_device_with_integrity_and_parallel_ext4_stress_using_luks2() {
        let temp_device = TempFileLoopDevice::new(56 * 1024 * 1024 * 1024).unwrap();
        let device_path = temp_device.dev_path().to_string();
        let _header_guard = remove_luks_header_on_drop(&device_path);
        let mapper_name = format!("luks2-loop-stress-test-{}", std::process::id());
        let _mapper_guard = CloseDeviceOnDrop(mapper_name.clone());
        let mut bd = BlockDevice::default();

        let options = HashMap::from([
            ("sourceType".to_string(), "empty".to_string()),
            ("targetType".to_string(), "fileSystem".to_string()),
            ("devicePath".to_string(), device_path),
            ("encryptionType".to_string(), "luks2".to_string()),
            (
                "key".to_string(),
                "file://./test_files/luks2-disk-passphrase".to_string(),
            ),
            ("mapperName".to_string(), mapper_name.clone()),
            ("dataIntegrity".to_string(), "true".to_string()),
            ("filesystemType".to_string(), "ext4".to_string()),
            ("mkfsOpts".to_string(), EXT4_INTEGRITY_MKFS_OPTS.to_string()),
        ]);

        let tempdir = TempDir::new().unwrap();
        let result = bd
            .real_mount(&options, &[], tempdir.path().to_str().unwrap())
            .await;
        if result.is_err() {
            close_luks_device(&mapper_name);
        }
        result.unwrap();

        let stress_result = run_ext4_stress(tempdir.path(), PARALLEL_EXT4_STRESS).await;
        let umount_result = bd.umount().await;
        close_luks_device_after_unmount(&mapper_name).await;

        umount_result.unwrap();
        stress_result.unwrap();
    }

    #[tokio::test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    #[serial]
    async fn encrypt_a_loop_device_with_integrity_and_single_worker_ext4_stress_using_luks2() {
        let temp_device = TempFileLoopDevice::new(56 * 1024 * 1024 * 1024).unwrap();
        let device_path = temp_device.dev_path().to_string();
        let _header_guard = remove_luks_header_on_drop(&device_path);
        let mapper_name = format!(
            "luks2-loop-single-worker-stress-test-{}",
            std::process::id()
        );
        let _mapper_guard = CloseDeviceOnDrop(mapper_name.clone());
        let mut bd = BlockDevice::default();

        let options = HashMap::from([
            ("sourceType".to_string(), "empty".to_string()),
            ("targetType".to_string(), "fileSystem".to_string()),
            ("devicePath".to_string(), device_path),
            ("encryptionType".to_string(), "luks2".to_string()),
            (
                "key".to_string(),
                "file://./test_files/luks2-disk-passphrase".to_string(),
            ),
            ("mapperName".to_string(), mapper_name.clone()),
            ("dataIntegrity".to_string(), "true".to_string()),
            ("filesystemType".to_string(), "ext4".to_string()),
            ("mkfsOpts".to_string(), EXT4_INTEGRITY_MKFS_OPTS.to_string()),
        ]);

        let tempdir = TempDir::new().unwrap();
        let result = bd
            .real_mount(&options, &[], tempdir.path().to_str().unwrap())
            .await;
        if result.is_err() {
            close_luks_device(&mapper_name);
        }
        result.unwrap();

        let stress_result = run_ext4_stress(tempdir.path(), SINGLE_WORKER_EXT4_STRESS).await;
        let umount_result = bd.umount().await;
        close_luks_device_after_unmount(&mapper_name).await;

        umount_result.unwrap();
        stress_result.unwrap();
    }

    #[tokio::test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    #[serial]
    async fn encrypt_an_empty_device_using_luks2() {
        use rand::{distr::Alphanumeric, rng, RngExt};
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

    #[tokio::test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    #[serial]
    async fn open_pre_encrypted_device_using_luks2_with_key() {
        use crate::storage::drivers::luks2::Luks2Formatter;
        use rand::{distr::Alphanumeric, rng, RngExt};
        use std::{io::Write, path::Path};
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

    #[tokio::test]
    #[cfg_attr(target_arch = "s390x", ignore)]
    #[serial]
    async fn encrypt_empty_device_without_key_uses_random_key() {
        use rand::{distr::Alphanumeric, rng, RngExt};
        use std::{io::Write, path::Path};

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
