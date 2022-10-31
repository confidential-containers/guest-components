// Copyright (c) 2022 Alibaba Cloud
// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use image_rs::image::IMAGE_SECURITY_CONFIG_DIR;
use std::path::Path;
use std::process::{Child, Command};
use strum_macros::{AsRefStr, EnumString};

/// Script for preparing Simple Signing GPG signature file.
const SIGNATURE_SCRIPT: &str = "scripts/install_test_signatures.sh";

/// Script for preparing resources.json for offline-fs-kbc.
const OFFLINE_FS_KBC_RESOURCE_SCRIPT: &str = "scripts/install_offline_fs_kbc_files.sh";

/// Parameter `decrypt_config`'s prefix provided for `ImageClient`.
const AA_PARAMETERS_PREFIX: &str = "provider:attestation-agent";

/// Parameter `decrypt_config`'s suffix provided for `ImageClient`.
const AA_PARAMETERS_KBC_URL: &str = "null";

#[derive(EnumString, AsRefStr, Debug)]
pub enum KBC {
    #[strum(to_string = "sample_kbc")]
    Sample,
    #[strum(to_string = "offline_fs_kbc")]
    OfflineFs,
}

impl KBC {
    pub fn aa_parameter(&self) -> String {
        format!(
            "{}:{}::{}",
            AA_PARAMETERS_PREFIX,
            self.as_ref(),
            AA_PARAMETERS_KBC_URL
        )
    }

    pub fn prepare_test(&self) {
        // Check whether is in root privilege
        assert!(
            nix::unistd::Uid::effective().is_root(),
            "The test needs to run as root."
        );

        // Prepare files
        Command::new(SIGNATURE_SCRIPT)
            .arg("install")
            .output()
            .expect("Install GPG signature file failed.");

        match self {
            KBC::Sample => {}
            KBC::OfflineFs => {
                Command::new(OFFLINE_FS_KBC_RESOURCE_SCRIPT)
                    .arg("install")
                    .output()
                    .expect("Install offline-fs-kbcs's resources failed.");
            }
        }
    }

    pub fn clean(&self) {
        match self {
            KBC::Sample => {}
            KBC::OfflineFs => {
                Command::new(OFFLINE_FS_KBC_RESOURCE_SCRIPT)
                    .arg("clean")
                    .output()
                    .expect("Clean offline-fs-kbcs's resources failed.");
            }
        }

        // Clean files
        Command::new(SIGNATURE_SCRIPT)
            .arg("clean")
            .output()
            .expect("Clean GPG signature file failed.");
    }
}

pub fn start_attestation_agent() -> Result<Child> {
    let script_dir = format!("{}/{}", std::env!("CARGO_MANIFEST_DIR"), "scripts");
    let aa_path = format!("{}/{}", script_dir, "attestation-agent");

    if !Path::new(&aa_path).exists() {
        let script_path = format!("{}/{}", script_dir, "build_attestation_agent.sh");
        Command::new(script_path)
            .output()
            .expect("Failed to build attestation-agent");
    }

    Ok(Command::new(aa_path)
        .args(&["--keyprovider_sock"])
        .args(&["127.0.0.1:50000"])
        .args(&["--getresource_sock"])
        .args(&["127.0.0.1:50001"])
        .spawn()?)
}

pub async fn clean_configs() -> Result<()> {
    if Path::new(IMAGE_SECURITY_CONFIG_DIR).exists() {
        tokio::fs::remove_dir_all(IMAGE_SECURITY_CONFIG_DIR).await?;
    }

    Ok(())
}
