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

/// Attestation Agent Offline Filesystem KBC resources file for general tests that use images stored in the quay.io registry
pub const OFFLINE_FS_KBC_RESOURCES_FILE: &str = "aa-offline_fs_kbc-resources.json";

/// Attestation Agent Offline Filesystem KBC resources file for XRSS tests
#[cfg(feature = "signature-simple-xrss")]
pub const AA_OFFLINE_FS_KBC_RESOURCES_FILE_XRSS: &str = "aa-offline_fs_kbc-resources-for-icr.json";

pub async fn prepare_test(offline_fs_kbc_resources: &str) {
    // Check whether is in root privilege
    assert!(
        nix::unistd::Uid::effective().is_root(),
        "The test needs to run as root."
    );

    // Prepare files
    Command::new(SIGNATURE_SCRIPT)
        .arg("install")
        .output()
        .await
        .expect("Install GPG signature file failed.");

    Command::new(OFFLINE_FS_KBC_RESOURCE_SCRIPT)
        .arg("install")
        .arg(offline_fs_kbc_resources)
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

pub async fn start_confidential_data_hub() -> Result<Child> {
    let script_dir = format!("{}/{}", std::env!("CARGO_MANIFEST_DIR"), "scripts");
    cfg_if::cfg_if! {
        if #[cfg(feature = "keywrap-ttrpc")] {
            let cdh_path = format!("{}/ttrpc/{}", script_dir, "confidential-data-hub");
        } else {
            let cdh_path = format!("{}/grpc/{}", script_dir, "confidential-data-hub");
        }
    };
    println!("cdh_path: {}", cdh_path);
    println!("script_dir: {}", script_dir);

    if !Path::new(&cdh_path).exists() {
        let script_path = format!("{}/{}", script_dir, "build_confidential_data_hub.sh");
        cfg_if::cfg_if! {
            if #[cfg(feature = "keywrap-ttrpc")] {
                let output = Command::new(script_path)
                    .env("TTRPC", "1")
                    .output()
                    .await
                    .expect("Failed to build confidential-data-hub");
                println!("build ttrpc confidential-data-hub: {:?}", output);
            } else {
                let output = Command::new(script_path)
                    .output()
                    .await
                    .expect("Failed to build confidential-data-hub");
                println!("build grpc confidential-data-hub: {:?}", output);
            }
        }
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "keywrap-ttrpc")] {
            let mut cdh = Command::new(cdh_path)
            .kill_on_drop(true)
            .spawn()
            .expect("Failed to start confidential-data-hub");
        } else {
            // TODO: implement this after CDH supports gRPC
            let mut cdh = Command::new(cdh_path)
            .kill_on_drop(true)
            .spawn()
            .expect("Failed to start confidential-data-hub");
        }
    };

    // Leave some time to let fork-ed AA process to be ready
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    if (cdh.try_wait()?).is_some() {
        panic!("Confidential Data Hub failed to start");
    }
    Ok(cdh)
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
