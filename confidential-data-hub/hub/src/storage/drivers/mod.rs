// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{
    io::Write,
    process::{Command, Stdio},
};

use anyhow::{anyhow, bail, Result};
use tempfile::NamedTempFile;
use tracing::debug;

pub mod filesystem;
#[cfg(feature = "luks2")]
pub mod luks2;
pub mod zfs;

/// Run a command and return the stdout and stderr.
pub fn run_command(
    command: &str,
    args: &[&str],
    inputs: Option<Vec<u8>>,
) -> Result<(String, String)> {
    let mut status = Command::new(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(args)
        .spawn()?;

    if let Some(inputs) = inputs {
        if let Some(mut stdin) = status.stdin.take() {
            stdin.write_all(&inputs)?;
            stdin.flush()?;
        } else {
            bail!(
                "Failed to get stdin from the command thus failed to write inputs to the command"
            );
        }
    }

    let output = status.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).replace("\n", "\n\t");
    let stderr = String::from_utf8_lossy(&output.stderr).replace("\n", "\n\t");

    if !output.status.success() {
        bail!(
            "Failed to run command {command} with args: {args:#?}\nstdout: {stdout}\nstderr: {stderr}",
        );
    }

    debug!("command {command} with args: {args:#?} \n\t stdout: {stdout} \n\t stderr: {stderr}");

    Ok((stdout, stderr))
}

/// A wrapper for the loop device backed by a temporary file.
pub struct TempFileLoopDevice {
    _file: NamedTempFile,
    loop_path: String,
}

impl TempFileLoopDevice {
    /// Create a new loop device.
    pub fn new(size_bytes: u64) -> Result<Self> {
        let file = NamedTempFile::new()?;
        file.as_file().set_len(size_bytes)?;

        let path = file
            .path()
            .to_str()
            .ok_or_else(|| anyhow!("failed to get path of the temporary file"))?;
        let (stdout, _) = run_command("losetup", &["--find", "--show", path], None)?;

        let loop_path = stdout.trim().to_string();

        Ok(Self {
            _file: file,
            loop_path,
        })
    }

    pub fn dev_path(&self) -> &str {
        &self.loop_path
    }
}

impl Drop for TempFileLoopDevice {
    fn drop(&mut self) {
        let _ = run_command("losetup", &["-d", self.loop_path.as_str()], None).unwrap();
    }
}
