// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::fs::File;
use std::path::{Path, PathBuf};

use crate::snapshots::SnapshotType;

pub const DEFAULT_WORK_DIR: &str = "/run/image-rs/";

/// Default policy file path.
pub const POLICY_FILE_PATH: &str = "kbs:///default/security-policy/test";

pub const SIG_STORE_CONFIG_DEFAULT_FILE: &str = "kbs:///default/sigstore-config/test";

/// The reason for using the `/run` directory here is that in general HW-TEE,
/// the `/run` directory is mounted in `tmpfs`, which is located in the encrypted memory protected by HW-TEE.
/// [`AUTH_FILE_PATH`] shows the path to the `auth.json` file.
pub const AUTH_FILE_PATH: &str = "kbs:///default/credential/test";

/// Default max concurrent download.
pub const DEFAULT_MAX_CONCURRENT_DOWNLOAD: usize = 3;

/// Path to the configuration file to generate ImageConfiguration
pub const CONFIGURATION_FILE_NAME: &str = "config.json";

/// `image-rs` configuration information.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ImageConfig {
    /// The location for `image-rs` to store data.
    #[serde(default = "default_work_dir")]
    pub work_dir: PathBuf,

    /// The default snapshot for `image-rs` to use.
    #[serde(default = "SnapshotType::default")]
    pub default_snapshot: SnapshotType,

    /// If any image security policy would be used to control the image pulling
    /// like signature verification, this field is used to set the URI of the
    /// policy file.
    ///
    /// Now it supports two different forms:
    /// - `KBS URI`: the iamge security policy will be fetched from KBS.
    ///     e.g. [`POLICY_FILE_PATH`]
    /// - `Local Path`: the security policy will be fetched from somewhere locally.
    ///     e.g. `file:///etc/image-policy.json`.
    ///
    /// The policy follows the format of
    /// <https://github.com/containers/image/blob/main/docs/containers-policy.json.5.md>.
    ///
    /// At the same time, some enhencements based on CoCo is used, that is the
    /// `keyPath` field can be filled with a KBS URI like `kbs:///default/key/1`
    ///
    /// This value defaults to `None`.
    #[serde(default = "Option::default")]
    pub image_security_policy_uri: Option<String>,

    /// Sigstore config file URI for simple signing scheme.
    ///
    /// When `image_security_policy_uri` is set and `SimpleSigning` (signedBy) is
    /// used in the policy, the signatures of the images would be used for image
    /// signature validation. This policy will record where the signatures is.
    ///
    /// Now it supports two different forms:
    /// - `KBS URI`: the sigstore config file will be fetched from KBS,
    ///     e.g. [`SIG_STORE_CONFIG_DEFAULT_FILE`].
    /// - `Local Path`: the sigstore config file will be fetched from somewhere locally,
    ///     e.g. `file:///etc/simple-signing.yaml`.
    ///
    /// This value defaults to `None`.
    #[serde(default = "Option::default")]
    pub sigstore_config_uri: Option<String>,

    /// If any credential auth (Base) would be used to connect to download
    /// image from private registry, this field is used to set the URI of the
    /// credential file.
    ///
    /// Now it supports two different forms:
    /// - `KBS URI`: the registry auth will be fetched from KBS,
    ///     e.g. [`AUTH_FILE_PATH`].
    /// - `Local Path`: the registry auth will be fetched from somewhere locally,
    ///     e.g. `file:///etc/image-registry-auth.json`.
    ///
    /// This value defaults to `None`.
    #[serde(default = "Option::default")]
    pub authenticated_registry_credentials_uri: Option<String>,

    /// The maximum number of layers downloaded concurrently when
    /// pulling one specific image.
    ///
    /// This defaults to [`DEFAULT_MAX_CONCURRENT_DOWNLOAD`].
    #[serde(default = "default_max_concurrent_layer_downloads_per_image")]
    pub max_concurrent_layer_downloads_per_image: usize,

    /// Proxy that will be used to pull image
    ///
    /// This value defaults to `None`.
    pub image_pull_proxy: Option<String>,

    /// No proxy env that will be used to pull image.
    ///
    /// This will ensure that when we access the image registry with specified
    /// IPs, the `image_pull_proxy` will not be used.
    ///
    /// If `image_pull_proxy` is not set, this field will do nothing.
    ///
    /// This value defaults to `None`.
    pub skip_proxy_ips: Option<String>,

    /// Nydus services configuration
    #[serde(rename = "nydus")]
    pub nydus_config: Option<NydusConfig>,

    #[cfg(feature = "keywrap-native")]
    #[serde(default = "default_kbc")]
    pub kbc: String,

    #[cfg(feature = "keywrap-native")]
    #[serde(default = "default_kbs_uri")]
    pub kbs_uri: String,
}

macro_rules! __default_deserialization_value {
    ($name: ident, $type: ident, $value: expr) => {
        fn $name() -> $type {
            $value
        }
    };
}

__default_deserialization_value!(
    default_max_concurrent_layer_downloads_per_image,
    usize,
    DEFAULT_MAX_CONCURRENT_DOWNLOAD
);

__default_deserialization_value!(default_work_dir, PathBuf, PathBuf::from(DEFAULT_WORK_DIR));

#[cfg(feature = "keywrap-native")]
__default_deserialization_value!(default_kbc, String, "sample_kbc".into());

#[cfg(feature = "keywrap-native")]
__default_deserialization_value!(default_kbs_uri, String, "null".into());

impl Default for ImageConfig {
    // Construct a default instance of `ImageConfig`
    fn default() -> ImageConfig {
        ImageConfig {
            work_dir: PathBuf::from(DEFAULT_WORK_DIR.to_string()),
            #[cfg(feature = "snapshot-overlayfs")]
            default_snapshot: SnapshotType::Overlay,
            #[cfg(not(feature = "snapshot-overlayfs"))]
            default_snapshot: SnapshotType::Unknown,
            max_concurrent_layer_downloads_per_image: DEFAULT_MAX_CONCURRENT_DOWNLOAD,
            #[cfg(feature = "nydus")]
            nydus_config: Some(NydusConfig::default()),
            #[cfg(not(feature = "nydus"))]
            nydus_config: None,
            image_security_policy_uri: None,
            sigstore_config_uri: None,
            authenticated_registry_credentials_uri: None,
            image_pull_proxy: None,
            skip_proxy_ips: None,

            #[cfg(feature = "keywrap-native")]
            kbc: default_kbc(),

            #[cfg(feature = "keywrap-native")]
            kbs_uri: default_kbs_uri(),
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

/// Nydus daemon service configuration
/// support fs driver including fusedev and fscache.
#[derive(Clone, Debug, Deserialize, PartialEq)]
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
#[derive(Clone, Debug, Deserialize, PartialEq)]
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
#[derive(Clone, Debug, Deserialize, PartialEq)]
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
            config.max_concurrent_layer_downloads_per_image,
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
            "work_dir": "/run/image-rs/",
            "default_snapshot": "overlay",
            "image_security_policy_uri": "file:///etc/image-policy.json",
            "authenticated_registry_credentials_uri": "file:///etc/image-auth.json",
	        "max_concurrent_layer_downloads_per_image": 1
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
        assert_eq!(config.max_concurrent_layer_downloads_per_image, 1);
        assert_eq!(
            config.image_security_policy_uri,
            Some("file:///etc/image-policy.json".to_string())
        );
        assert_eq!(
            config.authenticated_registry_credentials_uri,
            Some("file:///etc/image-auth.json".to_string())
        );

        let invalid_config_file = tempdir.path().join("does-not-exist");
        assert!(!invalid_config_file.exists());

        let _ = ImageConfig::try_from(invalid_config_file.as_path()).is_err();
        assert!(!invalid_config_file.exists());
    }

    #[test]
    fn test_nydus_config_from_file() {
        let data = r#"{
            "work_dir": "/run/image-rs/",
            "default_snapshot": "overlay",
            "nydus": {
                "type": "fuse",
                "id": "nydus_id",
                "fuse": {
                    "fail_over_policy": "flush",
                    "fuse_threads": 4
                }
            },
            "max_concurrent_layer_downloads_per_image": 1
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
