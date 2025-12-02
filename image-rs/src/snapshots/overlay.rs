// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use nix::mount::MsFlags;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::snapshots::{MountPoint, Snapshotter};

#[derive(Debug)]
pub struct OverlayFs {
    data_dir: PathBuf,
}

impl OverlayFs {
    /// Create a new instance of [OverlayFs].
    pub fn new(work_dir: PathBuf) -> Self {
        let data_dir = work_dir.join(OVERLAYFS_FS_TYPE);
        OverlayFs { data_dir }
    }
}

const OVERLAYFS_FS_TYPE: &str = "overlay";

impl Snapshotter for OverlayFs {
    fn mount(&mut self, layer_path: &[&str], mount_path: &Path) -> Result<MountPoint> {
        let overlay_lowerdir = layer_path.join(":");

        // derive an index path from the mount materials and current time
        let mount_index = {
            let mut hasher = Sha256::new();
            hasher.update(layer_path.concat());
            hasher.update(mount_path.as_os_str().as_bytes());

            let now = SystemTime::now();
            let since_unix_epoch = now
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Time went backwards");

            let secs = since_unix_epoch.as_secs();
            let nanos = since_unix_epoch.subsec_nanos();

            let mut time_seed = Vec::new();
            time_seed.extend(&secs.to_le_bytes());
            time_seed.extend(&nanos.to_le_bytes());
            hasher.update(time_seed);
            hex::encode(hasher.finalize())
        };
        let work_dir = self.data_dir.join(mount_index);
        let overlay_upperdir = work_dir.join("upperdir");
        let overlay_workdir = work_dir.join("workdir");

        // TODO: enhance safety by safe-path
        if !self.data_dir.exists() {
            fs::create_dir_all(&self.data_dir)?;
        }
        fs::create_dir_all(&overlay_upperdir)?;
        fs::create_dir_all(&overlay_workdir)?;

        if !mount_path.exists() {
            fs::create_dir_all(mount_path)?;
        }

        let source = Path::new(OVERLAYFS_FS_TYPE);
        let flags = MsFlags::empty();
        let options = format!(
            "lowerdir={},upperdir={},workdir={}",
            overlay_lowerdir,
            overlay_upperdir.display(),
            overlay_workdir.display()
        );

        nix::mount::mount(
            Some(source),
            mount_path,
            Some(OVERLAYFS_FS_TYPE),
            flags,
            Some(options.as_str()),
        )
        .map_err(|e| {
            anyhow!(
                "failed to mount {:?} to {:?}, with error: {}",
                source,
                mount_path,
                e
            )
        })?;

        Ok(MountPoint {
            r#type: String::from(OVERLAYFS_FS_TYPE),
            mount_path: mount_path.to_path_buf(),
            work_dir,
        })
    }

    fn unmount(&self, mount_point: &MountPoint) -> Result<()> {
        nix::mount::umount(mount_point.mount_path.as_path())?;

        Ok(())
    }
}
