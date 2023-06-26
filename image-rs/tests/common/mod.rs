// Copyright (c) 2022 Alibaba Cloud
// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use image_rs::image::IMAGE_SECURITY_CONFIG_DIR;
use std::path::Path;
use tokio::process::{Child, Command};

/// Script for preparing Simple Signing GPG signature file.
const SIGNATURE_SCRIPT: &str = "scripts/install_test_signatures.sh";

/// Script for preparing resources.json for offline-fs-kbc.
const OFFLINE_FS_KBC_RESOURCE_SCRIPT: &str = "scripts/install_offline_fs_kbc_files.sh";

/// Attestation Agent Key Provider Parameter
pub const AA_PARAMETER: &str = "provider:attestation-agent:offline_fs_kbc::null";

const OFFLINE_FS_KBC_RESOURCE: &str = "aa-offline_fs_kbc-resources.json";

pub struct TempDirs {
    pub work_dir: tempfile::TempDir,
    pub bundle_dir: tempfile::TempDir,
}

impl TempDirs {
    pub fn new() -> Self {
        let work_dir = tempfile::tempdir().unwrap();
        let bundle_dir = tempfile::tempdir().unwrap();
        Self {
            work_dir,
            bundle_dir,
        }
    }
}

#[cfg(feature = "snapshot-overlayfs")]
impl Drop for TempDirs {
    fn drop(&mut self) {
        umount_bundle(&self.bundle_dir);
    }
}

pub fn assert_root_privilege() {
    // Check whether is in root privilege
    assert!(
        nix::unistd::Uid::effective().is_root(),
        "The test needs to run as root."
    );
}

pub async fn prepare_test() {
    assert_root_privilege();

    // Prepare files
    Command::new(SIGNATURE_SCRIPT)
        .arg("install")
        .output()
        .await
        .expect("Install GPG signature file failed.");

    Command::new(OFFLINE_FS_KBC_RESOURCE_SCRIPT)
        .arg("install")
        .arg(OFFLINE_FS_KBC_RESOURCE)
        .output()
        .await
        .expect("Install offline-fs-kbcs's resources failed.");
}

pub async fn clean() {
    Command::new(OFFLINE_FS_KBC_RESOURCE_SCRIPT)
        .arg("clean")
        .output()
        .await
        .expect("Clean offline-fs-kbcs's resources failed.");

    // Clean files
    Command::new(SIGNATURE_SCRIPT)
        .arg("clean")
        .output()
        .await
        .expect("Clean GPG signature file failed.");
}

pub async fn start_attestation_agent() -> Result<Child> {
    let script_dir = format!("{}/{}", std::env!("CARGO_MANIFEST_DIR"), "scripts");
    let aa_path = format!("{}/{}", script_dir, "attestation-agent");

    if !Path::new(&aa_path).exists() {
        let script_path = format!("{}/{}", script_dir, "build_attestation_agent.sh");
        cfg_if::cfg_if! {
            if #[cfg(feature = "keywrap-ttrpc")] {
                Command::new(script_path)
                    .env("TTRPC", "1")
                    .output()
                    .await
                    .expect("Failed to build attestation-agent");
            } else {
                let output = Command::new(script_path)
                    .output()
                    .await
                    .expect("Failed to build attestation-agent");
            }
        }
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "keywrap-ttrpc")] {
            let mut aa = tokio::process::Command::new(aa_path)
                .kill_on_drop(true)
                .args(&[
                    "--keyprovider_sock",
                    "unix:///run/confidential-containers/attestation-agent/keyprovider.sock",
                    "--getresource_sock",
                    "unix:///run/confidential-containers/attestation-agent/getresource.sock"
                    ])
                .spawn()?;
        } else {
            let mut aa = tokio::process::Command::new(aa_path)
                .kill_on_drop(true)
                .args(&[
                    "--keyprovider_sock",
                    "127.0.0.1:50000",
                    "--getresource_sock",
                    "127.0.0.1:50001"
                    ])
                .spawn()?;
        }
    };

    // Leave some time to let fork-ed AA process to be ready
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    if let Some(_) = aa.try_wait()? {
        panic!("Attestation Agent failed to start");
    }
    Ok(aa)
}

pub fn umount_bundle(bundle_dir: &tempfile::TempDir) {
    let rootfs_path = bundle_dir.path().join("rootfs");
    nix::mount::umount(&rootfs_path).expect("failed to umount rootfs");
}

pub async fn clean_configs() -> Result<()> {
    if Path::new(IMAGE_SECURITY_CONFIG_DIR).exists() {
        tokio::fs::remove_dir_all(IMAGE_SECURITY_CONFIG_DIR).await?;
    }

    Ok(())
}
