// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::convert::TryFrom;
use std::fs::File;
use std::path::{Path, PathBuf};

use crate::snapshots::SnapshotType;
use crate::CC_IMAGE_WORK_DIR;

const DEFAULT_WORK_DIR: &str = "/var/lib/image-rs/";

/// `image-rs` configuration information.
#[derive(Clone, Debug, Deserialize)]
pub struct ImageConfig {
    /// The location for `image-rs` to store data.
    pub work_dir: PathBuf,

    /// The default snapshot for `image-rs` to use.
    pub default_snapshot: SnapshotType,

    /// Security validation control
    pub security_validate: bool,
}

impl Default for ImageConfig {
    // Construct a default instance of `ImageConfig`
    fn default() -> ImageConfig {
        let work_dir = PathBuf::from(
            std::env::var(CC_IMAGE_WORK_DIR).unwrap_or_else(|_| DEFAULT_WORK_DIR.to_string()),
        );
        ImageConfig {
            work_dir,
            default_snapshot: SnapshotType::Overlay,
            security_validate: false,
        }
    }
}

impl TryFrom<&Path> for ImageConfig {
    /// Load `ImageConfig` from a configuration file like:
    ///    {
    ///        "work_dir": "/var/lib/image-rs/",
    ///        "default_snapshot": "overlay"
    ///    }
    type Error = anyhow::Error;
    fn try_from(config_path: &Path) -> Result<Self, Self::Error> {
        let file = File::open(config_path)
            .map_err(|e| anyhow!("failed to open config file {}", e.to_string()))?;

        serde_json::from_reader::<File, ImageConfig>(file)
            .map_err(|e| anyhow!("failed to parse config file {}", e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::prelude::*;
    use tempfile;

    #[test]
    fn test_image_config() {
        let config = ImageConfig::default();
        let work_dir = PathBuf::from(DEFAULT_WORK_DIR);

        assert_eq!(config.work_dir, work_dir);
        assert_eq!(config.default_snapshot, SnapshotType::Overlay);

        let env_work_dir = "/tmp";
        std::env::set_var(CC_IMAGE_WORK_DIR, env_work_dir);
        let config = ImageConfig::default();
        let work_dir = PathBuf::from(env_work_dir);
        assert_eq!(config.work_dir, work_dir);
    }

    #[test]
    fn test_image_config_from_file() {
        let data = r#"{
            "work_dir": "/var/lib/image-rs/",
            "default_snapshot": "overlay",
            "security_validate": false
        }"#;

        let tempdir = tempfile::tempdir().unwrap();
        let config_file = tempdir.path().join("config.json");

        File::create(&config_file)
            .unwrap()
            .write_all(data.as_bytes())
            .unwrap();

        let config = ImageConfig::try_from(config_file.as_path()).unwrap();
        let work_dir = PathBuf::from(DEFAULT_WORK_DIR);

        assert_eq!(config.work_dir, work_dir);
        assert_eq!(config.default_snapshot, SnapshotType::Overlay);
    }
}
