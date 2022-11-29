// Copyright (c) 2022 Alibaba Cloud
// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use image_rs::image::IMAGE_SECURITY_CONFIG_DIR;
use std::path::Path;
use strum_macros::{AsRefStr, EnumString};
use tokio::process::{Child, Command};

/// Script for preparing Simple Signing GPG signature file.
const SIGNATURE_SCRIPT: &str = "scripts/install_test_signatures.sh";

/// Script for preparing resources.json for offline-fs-kbc.
const OFFLINE_FS_KBC_RESOURCE_SCRIPT: &str = "scripts/install_offline_fs_kbc_files.sh";

/// Parameter `decrypt_config`'s prefix provided for `ImageClient`.
const AA_PARAMETERS_PREFIX: &str = "provider:attestation-agent";

/// Parameter `decrypt_config`'s suffix provided for `ImageClient`.
const AA_PARAMETERS_KBC_URL: &str = "null";

#[derive(EnumString, AsRefStr, Debug)]
pub enum KbcType {
    #[strum(to_string = "sample_kbc")]
    Sample,
    #[strum(to_string = "offline_fs_kbc")]
    OfflineFs,
}

#[derive(Debug)]
pub struct KBC {
    pub kbc_type: KbcType,
    pub resources_file: String,
}

impl KBC {
    pub fn aa_parameter(&self) -> String {
        format!(
            "{}:{}::{}",
            AA_PARAMETERS_PREFIX,
            self.kbc_type.as_ref(),
            AA_PARAMETERS_KBC_URL
        )
    }

    pub async fn prepare_test(&self) {
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

        match self.kbc_type {
            KbcType::Sample => {}
            KbcType::OfflineFs => {
                Command::new(OFFLINE_FS_KBC_RESOURCE_SCRIPT)
                    .arg("install")
                    .arg(&self.resources_file)
                    .output()
                    .await
                    .expect("Install offline-fs-kbcs's resources failed.");
            }
        }
    }

    pub async fn clean(&self) {
        match self.kbc_type {
            KbcType::Sample => {}
            KbcType::OfflineFs => {
                Command::new(OFFLINE_FS_KBC_RESOURCE_SCRIPT)
                    .arg("clean")
                    .output()
                    .await
                    .expect("Clean offline-fs-kbcs's resources failed.");
            }
        }

        // Clean files
        Command::new(SIGNATURE_SCRIPT)
            .arg("clean")
            .output()
            .await
            .expect("Clean GPG signature file failed.");
    }
}

pub async fn start_attestation_agent() -> Result<Child> {
    let script_dir = format!("{}/{}", std::env!("CARGO_MANIFEST_DIR"), "scripts");
    let aa_path = format!("{}/{}", script_dir, "attestation-agent");

    if !Path::new(&aa_path).exists() {
        let script_path = format!("{}/{}", script_dir, "build_attestation_agent.sh");
        Command::new(script_path)
            .output()
            .await
            .expect("Failed to build attestation-agent");
    }

    let aa = tokio::process::Command::new(aa_path)
        .args(&["--keyprovider_sock"])
        .args(&["127.0.0.1:50000"])
        .args(&["--getresource_sock"])
        .args(&["127.0.0.1:50001"])
        .spawn()?;

    // Leave some time to let fork-ed AA process to be ready
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    Ok(aa)
}

pub async fn clean_configs() -> Result<()> {
    if Path::new(IMAGE_SECURITY_CONFIG_DIR).exists() {
        tokio::fs::remove_dir_all(IMAGE_SECURITY_CONFIG_DIR).await?;
    }

    Ok(())
}
