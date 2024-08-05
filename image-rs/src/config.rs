// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use serde::{Deserialize, Deserializer};
use std::fs::File;
use std::path::{Path, PathBuf};

use crate::snapshots::SnapshotType;

pub const DEFAULT_WORK_DIR: &str = "/var/lib/image-rs/";

/// Default policy file path.
pub const POLICY_FILE_PATH: &str = "kbs:///default/security-policy/test";

/// Dir of Sigstore Config file.
/// The reason for using the `/run` directory here is that in general HW-TEE,
/// the `/run` directory is mounted in `tmpfs`, which is located in the encrypted memory protected by HW-TEE.
pub const SIG_STORE_CONFIG_DIR: &str = "/run/image-security/simple_signing/sigstore_config";

pub const SIG_STORE_CONFIG_DEFAULT_FILE: &str = "kbs:///default/sigstore-config/test";

/// Path to the gpg pubkey ring of the signature
pub const GPG_KEY_RING: &str = "/run/image-security/simple_signing/pubkey.gpg";

/// The reason for using the `/run` directory here is that in general HW-TEE,
/// the `/run` directory is mounted in `tmpfs`, which is located in the encrypted memory protected by HW-TEE.
/// [`AUTH_FILE_PATH`] shows the path to the `auth.json` file.
pub const AUTH_FILE_PATH: &str = "kbs:///default/credential/test";

/// Default max concurrent download.
pub const DEFAULT_MAX_CONCURRENT_DOWNLOAD: usize = 3;

/// Path to the configuration file to generate ImageConfiguration
pub const CONFIGURATION_FILE_NAME: &str = "config.json";

/// `image-rs` configuration information.
#[derive(Clone, Debug, Deserialize)]
pub struct ImageConfig {
    /// The location for `image-rs` to store data.
    pub work_dir: PathBuf,

    /// The default snapshot for `image-rs` to use.
    pub default_snapshot: SnapshotType,

    /// Security validation control
    pub security_validate: bool,

    /// Use `auth.json` control
    pub auth: bool,

    /// Records different configurable paths
    #[serde(
        default = "Paths::default",
        deserialize_with = "deserialize_null_default"
    )]
    pub file_paths: Paths,

    /// Maximum number of concurrent downloads to perform during image pull.
    ///
    /// This defaults to [`DEFAULT_MAX_CONCURRENT_DOWNLOAD`].
    pub max_concurrent_download: usize,

    /// Nydus services configuration
    #[serde(rename = "nydus")]
    pub nydus_config: Option<NydusConfig>,
}

/// This function used to parse from string. When it is an
/// empty string, return the default value of the parsed
/// struct.
fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    T: Default + Deserialize<'de>,
    D: Deserializer<'de>,
{
    let opt = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

impl Default for ImageConfig {
    // Construct a default instance of `ImageConfig`
    fn default() -> ImageConfig {
        ImageConfig {
            work_dir: PathBuf::from(DEFAULT_WORK_DIR.to_string()),
            #[cfg(feature = "snapshot-overlayfs")]
            default_snapshot: SnapshotType::Overlay,
            #[cfg(not(feature = "snapshot-overlayfs"))]
            default_snapshot: SnapshotType::Unknown,
            security_validate: false,
            auth: false,
            file_paths: Paths::default(),
            max_concurrent_download: DEFAULT_MAX_CONCURRENT_DOWNLOAD,
            #[cfg(feature = "nydus")]
            nydus_config: Some(NydusConfig::default()),
            #[cfg(not(feature = "nydus"))]
            nydus_config: None,
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

        match serde_json::from_reader::<File, ImageConfig>(file) {
            Ok(image_config) => {
                if image_config.validate() {
                    Ok(image_config)
                } else {
                    Err(anyhow!("invalid configuration"))
                }
            }
            Err(e) => Err(anyhow!("failed to parse config file {}", e.to_string())),
        }
    }
}

impl ImageConfig {
    /// Construct an instance of `ImageConfig` with specific work directory.
    pub fn new(image_work_dir: PathBuf) -> Self {
        Self {
            work_dir: image_work_dir,
            ..Default::default()
        }
    }
    /// Validate the configuration object.
    pub fn validate(&self) -> bool {
        if let Some(nydus_cfg) = self.nydus_config.as_ref() {
            if !nydus_cfg.validate() {
                return false;
            }
        }

        true
    }

    pub fn get_nydus_config(&self) -> Result<&NydusConfig> {
        self.nydus_config
            .as_ref()
            .ok_or_else(|| anyhow!("no configuration information for nydus"))
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Paths {
    /// sigstore config file for simple signing
    pub sigstore_config: String,

    /// Path to `Policy.json`
    pub policy_path: String,

    /// Path to the auth file
    pub auth_file: String,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            sigstore_config: SIG_STORE_CONFIG_DEFAULT_FILE.into(),
            policy_path: POLICY_FILE_PATH.into(),
            auth_file: AUTH_FILE_PATH.into(),
        }
    }
}

/// Nydus daemon service configuration
/// support fs driver including fusedev and fscache.
#[derive(Clone, Debug, Deserialize)]
pub struct NydusConfig {
    /// Type of daemon service
    #[serde(rename = "type")]
    pub driver_type: String,

    /// Service instance identifier
    pub id: Option<String>,

    /// Fuse service configuration
    #[serde(rename = "fuse")]
    pub fuse_config: Option<FuseConfig>,

    /// Fscache service configuration
    #[serde(rename = "fscache")]
    pub fscache_config: Option<FscacheConfig>,
}

impl Default for NydusConfig {
    fn default() -> Self {
        Self {
            driver_type: "fuse".to_string(),
            id: None,
            fuse_config: Some(FuseConfig::default()),
            fscache_config: None,
        }
    }
}

impl NydusConfig {
    /// Check whether the service type is `fuse`
    pub fn is_fuse(&self) -> bool {
        self.driver_type == "fuse"
    }

    /// Check whether the service type is `fscache`
    pub fn is_fscache(&self) -> bool {
        self.driver_type == "fscache"
    }

    pub fn get_fuse_config(&self) -> Result<&FuseConfig> {
        self.fuse_config
            .as_ref()
            .ok_or_else(|| anyhow!("no configuration information for fuse"))
    }

    pub fn get_fscache_config(&self) -> Result<&FscacheConfig> {
        self.fscache_config
            .as_ref()
            .ok_or_else(|| anyhow!("no configuration information for fscache"))
    }

    /// Validate the configuration object.
    pub fn validate(&self) -> bool {
        if self.driver_type != "fuse" && self.driver_type != "fscache" {
            return false;
        }

        if self.is_fuse() && self.fuse_config.is_none() {
            return false;
        }

        if self.is_fscache() && self.fscache_config.is_none() {
            return false;
        }

        true
    }
}

/// Nydus daemon fs backend configuration for fusedev
#[derive(Clone, Debug, Deserialize)]
pub struct FuseConfig {
    /// FUSE server failover policy
    pub fail_over_policy: String,

    /// Number of worker threads to serve FUSE I/O requests
    pub fuse_threads: u32,

    /// Path to the `localfs` working directory, which also enables the `localfs` storage backend
    pub localfs_dir: Option<PathBuf>,

    /// Path to the prefetch configuration file
    pub prefetch_files: Option<Vec<String>>,

    /// Mountpoint within the FUSE/virtiofs device to mount the RAFS/passthroughfs filesystem
    pub virtual_mountpoint: Option<PathBuf>,
}

impl Default for FuseConfig {
    fn default() -> Self {
        Self {
            fail_over_policy: "flush".to_string(),
            fuse_threads: 4,
            localfs_dir: None,
            prefetch_files: None,
            virtual_mountpoint: Some(PathBuf::from("/")),
        }
    }
}

/// Nydus daemon fs backend configuration for fusedev
#[derive(Clone, Debug, Deserialize)]
pub struct FscacheConfig {
    /// Working directory for Linux fscache driver to store cache files
    pub fscache: Option<PathBuf>,

    /// Working directory for Linux fscache driver to store cache files
    pub fscache_tag: Option<String>,

    /// Number of working threads to serve fscache requests
    pub fscache_threads: u32,
}

impl Default for FscacheConfig {
    fn default() -> Self {
        Self {
            fscache: None,
            fscache_tag: None,
            fscache_threads: 4,
        }
    }
}

#[cfg(feature = "snapshot-overlayfs")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::prelude::*;

    #[test]
    fn test_image_config() {
        let config = ImageConfig::default();
        let work_dir = PathBuf::from(DEFAULT_WORK_DIR);

        assert_eq!(config.work_dir, work_dir);
        assert_eq!(config.default_snapshot, SnapshotType::Overlay);
        assert_eq!(
            config.max_concurrent_download,
            DEFAULT_MAX_CONCURRENT_DOWNLOAD
        );

        let env_work_dir = "/tmp";
        let config = ImageConfig::new(PathBuf::from(env_work_dir));
        let work_dir = PathBuf::from(env_work_dir);
        assert_eq!(config.work_dir, work_dir);
    }

    #[test]
    fn test_image_config_from_file() {
        let data = r#"{
            "work_dir": "/var/lib/image-rs/",
            "default_snapshot": "overlay",
            "security_validate": false,
            "auth": false,
	    "max_concurrent_download": 1
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
        assert_eq!(config.max_concurrent_download, 1);

        let invalid_config_file = tempdir.path().join("does-not-exist");
        assert!(!invalid_config_file.exists());

        let _ = ImageConfig::try_from(invalid_config_file.as_path()).is_err();
        assert!(!invalid_config_file.exists());
    }

    #[test]
    fn test_nydus_config_from_file() {
        let data = r#"{
            "work_dir": "/var/lib/image-rs/",
            "default_snapshot": "overlay",
            "security_validate": false,
            "auth": false,
            "nydus": {
                "type": "fuse",
                "id": "nydus_id",
                "fuse": {
                    "fail_over_policy": "flush",
                    "fuse_threads": 4
                }
            },
            "max_concurrent_download": 1
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

        assert!(config.nydus_config.is_some());
        if let Ok(nydus_config) = config.get_nydus_config() {
            assert_eq!(nydus_config.id, Some("nydus_id".to_string()));

            assert!(nydus_config.fuse_config.is_some());
            if let Ok(fuse_config) = nydus_config.get_fuse_config() {
                assert_eq!(fuse_config.fuse_threads, 4)
            }
        }

        let invalid_config_file = tempdir.path().join("does-not-exist");
        assert!(!invalid_config_file.exists());

        let _ = ImageConfig::try_from(invalid_config_file.as_path()).is_err();
        assert!(!invalid_config_file.exists());
    }
}
