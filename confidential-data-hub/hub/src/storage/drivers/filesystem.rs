// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use strum::AsRefStr;
use tracing::warn;

use crate::storage::drivers::run_command;

const EXT4_COMMAND: &str = "mkfs.ext4";
const DD_COMMAND: &str = "dd";

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
            FsType::Ext4 => {
                if !is_ext4_installed() {
                    bail!("ext4 is not installed. Consider installing `e2fsprogs` (ubuntu).");
                }
                EXT4_COMMAND
            }
        };

        if !is_dd_installed() {
            bail!("dd is not installed. Consider installing `coreutils` (ubuntu).");
        }

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
                DD_COMMAND,
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

        // then do original format command with integrity-compatible defaults
        let format_args = match self.fs_type {
            FsType::Ext4 => disable_lazy_itable_init(&self.args),
        };
        self.format_with_args(device_path, &format_args)?;

        Ok(())
    }

    pub fn format(&self, device_path: &str) -> Result<()> {
        self.format_with_args(device_path, &self.args)
    }

    fn format_with_args(&self, device_path: &str, format_args: &[String]) -> Result<()> {
        let command = match self.fs_type {
            FsType::Ext4 => {
                if !is_ext4_installed() {
                    bail!("ext4 is not installed. Consider installing `e2fsprogs` (ubuntu).");
                }
                EXT4_COMMAND
            }
        };

        let mut args = vec![device_path];
        if self.force {
            args.push("-F");
        }
        for arg in format_args {
            args.push(arg);
        }

        let _ = run_command(command, &args, None)?;

        Ok(())
    }
}

// Keep explicit caller choices, but default ext4 to eager inode table initialization.
fn disable_lazy_itable_init(args: &[String]) -> Vec<String> {
    let mut args = args.to_vec();
    if args.iter().any(|arg| arg.contains("lazy_itable_init")) {
        return args;
    }

    warn!(
        "defaulting ext4 lazy_itable_init=0 for LUKS2 dm-integrity; set it explicitly in mkfsOpts to override"
    );

    if let Some(index) = args.iter().rposition(|arg| arg == "-E") {
        if let Some(options) = args.get_mut(index + 1) {
            options.push_str(",lazy_itable_init=0");
            return args;
        }
    }

    if let Some(options) = args
        .iter_mut()
        .rfind(|arg| arg.starts_with("-E") && arg.len() > 2)
    {
        options.push_str(",lazy_itable_init=0");
        return args;
    }

    args.push("-E".to_string());
    args.push("lazy_itable_init=0".to_string());
    args
}

fn is_ext4_installed() -> bool {
    let installed = run_command(EXT4_COMMAND, &["-V"], None).is_ok();
    if !installed {
        warn!("ext4 is not installed. Consider installing `e2fsprogs` (ubuntu).");
    }
    installed
}

fn is_dd_installed() -> bool {
    let installed = run_command(DD_COMMAND, &["--version"], None).is_ok();
    if !installed {
        warn!("dd is not installed. Consider installing `coreutils` (ubuntu).");
    }
    installed
}

#[cfg(test)]
mod tests {
    use super::disable_lazy_itable_init;

    #[test]
    fn ext4_args_add_lazy_itable_init_when_missing() {
        let args = vec!["-m".to_string(), "0".to_string()];
        assert_eq!(
            disable_lazy_itable_init(&args),
            vec![
                "-m".to_string(),
                "0".to_string(),
                "-E".to_string(),
                "lazy_itable_init=0".to_string()
            ]
        );
    }

    #[test]
    fn ext4_args_merge_lazy_itable_init_into_separate_extended_options() {
        let args = vec!["-E".to_string(), "nodiscard".to_string()];
        assert_eq!(
            disable_lazy_itable_init(&args),
            vec!["-E".to_string(), "nodiscard,lazy_itable_init=0".to_string()]
        );
    }

    #[test]
    fn ext4_args_merge_lazy_itable_init_into_combined_extended_options() {
        let args = vec!["-Enodiscard".to_string()];
        assert_eq!(
            disable_lazy_itable_init(&args),
            vec!["-Enodiscard,lazy_itable_init=0".to_string()]
        );
    }

    #[test]
    fn ext4_args_keep_caller_lazy_itable_init() {
        let args = vec!["-E".to_string(), "lazy_itable_init=1".to_string()];
        assert_eq!(disable_lazy_itable_init(&args), args);
    }
}
