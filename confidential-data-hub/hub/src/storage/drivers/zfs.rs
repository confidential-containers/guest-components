// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//
//! # ZFS
//!
//! This module leverages zfs to encrypt/decrypt a block device with zfs.
//!
//! It requires to install dependency `zfsutils-linux` for ubuntu and enable the zfs module in the kernel.
//!
//! Note that dataset means almost the same as a filesystem directory in zfs.
//!
//! ## Example
//!
//! If you want to create a zpool and a zdataset upon a block device, you can use the following code:
//! ```no_run
//! use confidential_data_hub::storage::drivers::zfs::{create_zpool, create_zdataset};
//! use zeroize::Zeroizing;
//!
//! create_zpool("test-pool", "/dev/loop0").unwrap();
//! create_zdataset("test-pool", "test-dataset", Zeroizing::new("<key-content>".as_bytes().to_vec()), "/mnt/test-dataset").unwrap();
//! ```
//!
//! Usually, you can stop here. If you want to do data migration, you can keep reading.
//!
//! Sync the data to the block device and export the zpool.
//!
//! ```no_run
//! use confidential_data_hub::storage::drivers::zfs::export_zpool;
//!
//! export_zpool("test-pool").unwrap();
//! ```
//!
//! Then you can move away the block device to another machine/environment and import the zpool again.
//! Suppose the block device is still `/dev/loop0`, the following code will import the zpool and mount the zdataset.
//! ```no_run
//! use confidential_data_hub::storage::drivers::zfs::{import_zpool, load_key, mount_dataset};
//! use zeroize::Zeroizing;
//!
//! import_zpool("test-pool", "/dev/loop0").unwrap();
//!
//! // If the dataset is encrypted, you need to load the key to the dataset first.
//! load_key("test-pool", "test-dataset", Zeroizing::new("<key-content>".as_bytes().to_vec())).unwrap();
//! mount_dataset("test-pool", "test-dataset", Some("/mnt/test-dataset")).unwrap();
//! ```

use std::{fs, io::Write};

use crate::storage::{drivers::run_command, volume_type::blockdevice::SourceType};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

/// The default name of the zpool.
pub const DEFAULT_ZPOOL_NAME: &str = "zpool";

/// The default name of the zdataset.
pub const DEFAULT_ZDATASET_NAME: &str = "zdataset";

/// The default encryption algorithm.
pub const DEFAULT_ENCRYPTION_ALGORITHM: &str = "aes-256-gcm";

/// The default encryption key format.
pub const DEFAULT_ENCRYPTION_KEY_FORMAT: &str = "passphrase";

fn default_pool_name() -> String {
    DEFAULT_ZPOOL_NAME.to_string()
}

fn default_dataset_name() -> String {
    DEFAULT_ZDATASET_NAME.to_string()
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Default)]
pub struct ZfsParameters {
    /// The name of the zpool to use.
    #[serde(default = "default_pool_name")]
    pub pool: String,

    /// The name of the zdataset to use.
    #[serde(default = "default_dataset_name")]
    pub dataset: String,
}

impl ZfsParameters {
    /// Mount the zfs pool and zdataset to the given mount point.
    /// Returns a vector of the created zfs pools.
    pub async fn do_mount(
        self,
        device_path: &str,
        mount_point: &str,
        key: Zeroizing<Vec<u8>>,
        source_type: SourceType,
    ) -> Result<()> {
        if !is_zfs_installed() {
            bail!("zfs is not installed. Please install zfsutils-linux and enable the zfs module in the kernel.");
        }

        debug!(
            pool = self.pool,
            dataset = self.dataset,
            mount_point = mount_point,
            "mounting zfs pool"
        );

        // if the source type is empty, create a new zpool and zdataset
        if source_type == SourceType::Empty {
            warn!("creating a new zpool and zdataset on the device. This will wipe original data on the disk.");
            create_zpool(&self.pool, device_path)?;
            create_zdataset(&self.pool, &self.dataset, key, mount_point)?;
        } else {
            // if the source type is encrypted, import the zpool and load the key to the zdataset
            info!("importing the zpool and loading the key to the zdataset on the device.");
            import_zpool(&self.pool, device_path)?;
            load_key(&self.pool, &self.dataset, key)?;
            mount_dataset(&self.pool, &self.dataset, Some(mount_point))?;
        }

        Ok(())
    }
}

/// This function checks if zfs is installed and available.
pub fn is_zfs_installed() -> bool {
    let installed = run_command("zpool", &["list"], None).is_ok();
    if !installed {
        warn!("zfs is not installed. Consider installing `zfsutils-linux` (ubuntu) and enable the zfs module in the kernel.");
    }
    installed
}

/// This function creates a zpool upon a block device.
pub fn create_zpool(pool_name: &str, device_path: &str) -> Result<()> {
    let (stdout, stderr) = run_command("zpool", &["create", "-f", pool_name, device_path], None)?;

    debug!("zpool create output: {stdout}");
    debug!("zpool create stderr: {stderr}");

    Ok(())
}

pub fn destroy_zpool(pool_name: &str) -> Result<()> {
    let (stdout, stderr) = run_command("zpool", &["destroy", pool_name], None)?;

    debug!("zpool destroy output: {stdout}");
    debug!("zpool destroy stderr: {stderr}");

    Ok(())
}

/// This function creates a zdataset upon a zpool.
/// It will also create a mount point and set the mount point to the zdataset.
pub fn create_zdataset(
    pool_name: &str,
    dataset_name: &str,
    key: Zeroizing<Vec<u8>>,
    mount_point: &str,
) -> Result<()> {
    fs::create_dir_all(mount_point).context("create mount point")?;
    let mut key_command = Vec::new();
    key_command.write_all(&key)?;
    key_command.write_all(b"\n")?;
    key_command.write_all(&key)?;
    key_command.write_all(b"\n")?;
    let (stdout, stderr) = run_command(
        "zfs",
        &[
            "create",
            "-o",
            &format!("encryption={DEFAULT_ENCRYPTION_ALGORITHM}"),
            "-o",
            &format!("keyformat={DEFAULT_ENCRYPTION_KEY_FORMAT}"),
            "-o",
            &format!("mountpoint={mount_point}"),
            &format!("{pool_name}/{dataset_name}"),
        ],
        Some(key_command),
    )?;

    debug!("zdataset create output: {stdout}");
    debug!("zdataset create stderr: {stderr}");

    Ok(())
}

/// This function imports a zpool from a block device.
pub fn import_zpool(pool_name: &str, device_path: &str) -> Result<()> {
    let (stdout, stderr) = run_command("zpool", &["import", "-d", device_path, pool_name], None)?;

    debug!("zpool import output: {stdout}");
    debug!("zpool import stderr: {stderr}");

    Ok(())
}

/// This function loads a key to a zdataset.
pub fn load_key(pool_name: &str, dataset_name: &str, key: Zeroizing<Vec<u8>>) -> Result<()> {
    let mut key_command = Vec::new();
    key_command.write_all(&key)?;
    key_command.write_all(b"\n")?;
    key_command.write_all(&key)?;
    key_command.write_all(b"\n")?;
    let (stdout, stderr) = run_command(
        "zfs",
        &["load-key", &format!("{pool_name}/{dataset_name}")],
        Some(key_command),
    )?;

    debug!("zdataset load key output: {stdout}");
    debug!("zdataset load key stderr: {stderr}");

    Ok(())
}

/// This function mounts a zdataset to a mount point.
/// If the mount point is not provided, the zdataset will be mounted to the default mount point.
pub fn mount_dataset(pool_name: &str, dataset_name: &str, mount_point: Option<&str>) -> Result<()> {
    // Sometimes the dateset will be mounted automatically.
    // We need to set the canmount property to noauto to prevent this.
    let (stdout, stderr) = run_command(
        "zfs",
        &[
            "set",
            "canmount=noauto",
            &format!("{pool_name}/{dataset_name}"),
        ],
        None,
    )?;

    debug!("zdataset set canmount output: {stdout}");
    debug!("zdataset set canmount stderr: {stderr}");

    if let Some(mount_point) = mount_point {
        let (stdout, stderr) = run_command(
            "zfs",
            &[
                "set",
                &format!("mountpoint={mount_point}"),
                &format!("{pool_name}/{dataset_name}"),
            ],
            None,
        )?;

        debug!("zdataset set mountpoint output: {stdout}");
        debug!("zdataset set mountpoint stderr: {stderr}");
    }

    let (stdout, stderr) = run_command(
        "zfs",
        &["mount", &format!("{pool_name}/{dataset_name}")],
        None,
    )?;

    debug!("zdataset mount output: {stdout}");
    debug!("zdataset mount stderr: {stderr}");

    Ok(())
}

/// This function exports a zpool.
pub fn export_zpool(pool_name: &str) -> Result<()> {
    let (stdout, stderr) = run_command("zpool", &["export", pool_name], None)?;

    debug!("zpool export output: {stdout}");
    debug!("zpool export stderr: {stderr}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::storage::{drivers::TempFileLoopDevice, tests::init_tracing};

    use super::*;

    /// This performs a whole zfs flow:
    /// - create a zpool upon a block device
    /// - create a zdataset upon the zpool
    /// - write some data to the zdataset
    /// - export the zpool
    /// - import the zpool
    /// - load the key to the zdataset
    /// - mount the zdataset
    /// - read data from the zdataset
    /// - clean up
    #[test]
    fn test_whole_zfs_flow() {
        init_tracing();
        if !is_zfs_installed() {
            warn!("zfs is not installed. Skipping zfs flow test.");
            return;
        }

        let temp_device = TempFileLoopDevice::new(200 * 1024 * 1024).unwrap();

        const TEST_KEY: &str = include_str!("../../../test_files/zfs-disk-passphrase");
        let key = Zeroizing::new(TEST_KEY.as_bytes().to_vec());
        const TEST_DATA: &str = "test data";

        let device_path = temp_device.dev_path();

        // 1. create a zpool upon a block device
        create_zpool("test-pool", device_path).unwrap();

        // 2. create a zdataset upon the zpool
        create_zdataset(
            "test-pool",
            "test-dataset",
            key.clone(),
            "/mnt/test-dataset",
        )
        .unwrap();

        // 3. write some data to the zdataset
        fs::write("/mnt/test-dataset/test-file", TEST_DATA).unwrap();

        // 4. export the zpool
        export_zpool("test-pool").unwrap();

        // 5. import the zpool
        import_zpool("test-pool", device_path).unwrap();

        // 6. load the key to the zdataset
        load_key("test-pool", "test-dataset", key).unwrap();

        // 7. mount the zdataset
        mount_dataset("test-pool", "test-dataset", Some("/mnt/test-dataset")).unwrap();

        // 8. read data from the zdataset
        let data = fs::read("/mnt/test-dataset/test-file").unwrap();
        assert_eq!(data, TEST_DATA.as_bytes());

        // 9. clean up
        destroy_zpool("test-pool").unwrap();
    }
}
