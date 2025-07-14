// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::process::Stdio;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use strum::AsRefStr;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Copy, AsRefStr)]
pub enum FsType {
    #[strum(serialize = "ext4")]
    #[serde(rename = "ext4")]
    Ext4,
}

#[derive(Debug)]
pub struct FsFormatter {
    pub fs_type: FsType,
    pub force: bool,
    pub args: Vec<String>,
}

impl FsFormatter {
    pub async fn format(&self, device_path: &str) -> Result<()> {
        let command = match self.fs_type {
            FsType::Ext4 => "mkfs.ext4",
        };

        let mut args = vec![device_path];
        if self.force {
            args.push("-F");
        }
        for arg in &self.args {
            args.push(arg);
        }

        let status = Command::new(command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .args(&args)
            .spawn()
            .context(format!(
                "Failed to format device {device_path} with options:\n {self:#?}"
            ))?;

        let output = status.wait_with_output().await?;
        let stdout = String::from_utf8_lossy(&output.stdout).replace("\n", "\n\t");
        let stderr = String::from_utf8_lossy(&output.stderr).replace("\n", "\n\t");

        if !output.status.success() {
            bail!(
                "Failed to format device {device_path} with options:\n {self:#?}\nstdout: {stdout}\nstderr: {stderr}",
            );
        }

        Ok(())
    }
}
