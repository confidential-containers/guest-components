// Copyright (c) 2022 Alibaba Cloud
// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use signature::agent::IMAGE_SECURITY_CONFIG_DIR;
use std::path::Path;
use std::process::{Child, Command};

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
        .args(&["127.0.0.1:47777"])
        .args(&["--getresource_sock"])
        .args(&["127.0.0.1:48888"])
        .spawn()?)
}

pub async fn clean_configs() -> Result<()> {
    if Path::new(IMAGE_SECURITY_CONFIG_DIR).exists() {
        tokio::fs::remove_dir_all(IMAGE_SECURITY_CONFIG_DIR).await?;
    }

    Ok(())
}
