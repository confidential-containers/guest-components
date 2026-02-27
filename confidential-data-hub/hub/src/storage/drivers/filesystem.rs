// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use strum::AsRefStr;

use crate::storage::drivers::run_command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy, AsRefStr, Default)]
pub enum FsType {
    #[strum(serialize = "ext4")]
    #[serde(rename = "ext4")]
    #[default]
    Ext4,
}

#[derive(Debug)]
pub struct FsFormatter {
    pub fs_type: FsType,
    pub force: bool,
    pub args: Vec<String>,
}

impl FsFormatter {
    /// Wiping a device is a time consuming operation. To avoid a full wipe, integritysetup
    /// and crypt setup provide a --no-wipe option.
    /// However, an integrity device that is not wiped will have invalid checksums. Normally
    /// this should not be a problem since a page must first be written to before it can be read
    /// (otherwise the data would be arbitrary). The act of writing would populate the checksum
    /// for the page.
    /// However, tools like mkfs.ext4 read pages before they are written; sometimes the read
    /// of an unwritten page happens due to kernel buffering.
    /// See https://gitlab.com/cryptsetup/cryptsetup/-/issues/525 for explanation and fix.
    /// The way to propery format the non-wiped dm-integrity device is to figure out which pages
    /// mkfs.ext4 will write to and then to write to those pages before hand so that they will
    /// have valid integrity tags.
    /// `mkfs.ext4`` doesn't perform whole sector writes and this will cause checksum failures
    /// with an unwiped integrity device. Therefore, first perform a dry run.
    /// The above command will produce output like
    /// ```text
    /// mke2fs 1.46.5 (30-Dec-2021)
    /// Creating filesystem with 268435456 4k blocks and 67108864 inodes
    /// Filesystem UUID: 4a5ff012-91c0-47d9-b4bb-8f83e830825f
    /// Superblock backups stored on blocks:
    ///         32768, 98304, 163840, 229376, 294912, 819200, 884736, 1605632, 2654208,
    ///         4096000, 7962624, 11239424, 20480000, 23887872, 71663616, 78675968,
    ///         102400000, 214990848
    /// ```
    ///
    /// Thus we need to get the block numbers and write to those blocks before hand.
    pub fn format_integrity_compatible(&self, device_path: &str) -> Result<()> {
        let command = match self.fs_type {
            FsType::Ext4 => "mkfs.ext4",
        };
        let args = vec!["-F", "-n", device_path];
        let (stdout, stderr) = run_command(command, &args, None)?;

        // Get the block numbers
        let delimiter = "Superblock backups stored on blocks:";
        let start = stdout
            .find(delimiter)
            .map(|pos| pos + delimiter.len())
            .ok_or_else(|| anyhow!("Failed to get the block numbers: {stdout}\n{stderr}"))?;

        let tail = &stdout[start..];
        let mut nums: Vec<u64> = tail
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter_map(|tok| {
                let tok = tok.trim();
                if tok.is_empty() {
                    return None;
                }
                tok.trim_matches(|c: char| !c.is_ascii_digit())
                    .parse::<u64>()
                    .ok()
            })
            .collect();

        nums.push(0);
        nums.dedup();
        if nums.is_empty() {
            bail!("Failed to get the block numbers: {stdout}\n{stderr}");
        }

        for num in nums {
            let _ = run_command(
                "dd",
                &[
                    "if=/dev/zero",
                    &format!("of={device_path}"),
                    "bs=4k",
                    "count=1",
                    "oflag=direct",
                    &format!("seek={num}"),
                ],
                None,
            )?;
        }

        // then do original format command
        self.format(device_path)?;

        Ok(())
    }

    pub fn format(&self, device_path: &str) -> Result<()> {
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

        let _ = run_command(command, &args, None)?;

        Ok(())
    }
}
