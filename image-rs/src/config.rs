// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use log::debug;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use crate::registry::Config as RegistryConfig;
use crate::snapshots::SnapshotType;

/// By default use a work dir in `/run` because for confidential guests `/run`
/// is typically in a `tmpfs` which is backed by encrypted memory.
pub const DEFAULT_WORK_DIR: &str = "/run/kata-containers/image/";

/// Default path to policy file in KBS or locally
pub const POLICY_FILE_PATH: &str = "kbs:///default/security-policy/test";

/// Default path to sig store config in KBS or locally
pub const SIG_STORE_CONFIG_DEFAULT_FILE: &str = "kbs:///default/sigstore-config/test";

/// Default path to auth.json in KBS or locally
pub const AUTH_FILE_PATH: &str = "kbs:///default/credential/test";

/// Default max concurrent downloads
pub const DEFAULT_MAX_CONCURRENT_DOWNLOAD: usize = 3;

/// Path to the configuration file to generate ImageConfiguration
pub const CONFIGURATION_FILE_NAME: &str = "config.json";

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ProxyConfig {
    /// HTTPS proxy that will be used to pull image
    ///
    /// If a registry is not accessible to the guest, you can try
    /// pulling an image through a proxy specified here.
    ///
    /// This value defaults to `None`.
    #[serde(default)]
    pub https_proxy: Option<String>,

    /// HTTP proxy that will be used to pull image
    ///
    /// If a registry is not accessible to the guest, you can try
    /// pulling an image through a proxy specified here.
    ///
    /// This value defaults to `None`.
    #[serde(default)]
    pub http_proxy: Option<String>,

    /// If the above proxy is enabled, this field can be used to list IPs
    /// that will bypass the proxy.
    ///
    /// In other words all requests, except those made to these IPs,
    /// will go through the proxy.
    ///
    /// If `image_pull_proxy` is not set, this field will do nothing.
    ///
    /// This value defaults to `None`.
    #[serde(default)]
    pub no_proxy: Option<String>,
}

/// `image-rs` configuration information.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ImageConfig {
    /// The location for `image-rs` to store data.
    #[serde(default = "default_work_dir")]
    pub work_dir: PathBuf,

    /// The default snapshot for `image-rs` to use.
    #[serde(default = "SnapshotType::default")]
    pub default_snapshot: SnapshotType,

    /// An image security policy regulates which images can be pulled by image-rs
    /// and if/how images are validated when they are pulled.
    /// For example, a policy can require that images from a particular registry
    /// are signed with a particular scheme.
    ///
    /// The security policy follows a standard format described here:
    /// <https://github.com/containers/image/blob/main/docs/containers-policy.json.5.md>
    /// Some CoCo enhancements have been added.
    /// For instance the `keypath` field can be set to a resource URI such as
    /// `kbs:///default/key/1`.
    ///
    /// This field points to an image security policy.
    /// The policy can either be stored in a KBS and referenced via a resource URI
    /// or it can be stored locally (somewhere in the rootfs).
    ///
    /// For example, `file:///etc/image-policy.json` for a local policy file
    /// or `kbs:///default/policies/image-security-policy.json` for a policy
    /// file that has been provisioned to a KBS.
    ///
    /// If this field is not set (which is the default) no image security policy
    /// will be used. Images will not be validated when they are pulled.
    #[serde(default = "Option::default")]
    pub image_security_policy_uri: Option<String>,

    /// Sigstore config file URI for simple signing scheme.
    ///
    /// When `image_security_policy_uri` is set and `SimpleSigning` (signedBy) is
    /// used in the policy, an additional sigstore configuration file is needed.
    ///
    /// Like the above, the sigstore config can be stored locally in the rootfs
    /// or retrieved from the KBS.
    ///
    /// This value defaults to `None`.
    #[serde(default = "Option::default")]
    pub sigstore_config_uri: Option<String>,

    /// To pull an image from an authenticated/private registry, credentials
    /// must be provided to image-rs. This field points to a credential file,
    /// which can either be stored locally in the rootfs or retrieved from the KBS.
    ///
    /// This value defaults to `None`.
    #[serde(default = "Option::default")]
    pub authenticated_registry_credentials_uri: Option<String>,

    /// Registry configuration supports defining registry blocking, mirroring,
    /// and remapping rules. This field points to a registry configuration file,
    /// which can either be stored locally in the rootfs or retrieved from the KBS.
    ///
    /// This value defaults to `None`.
    #[serde(default = "Option::default")]
    pub registry_configuration_uri: Option<String>,

    /// Registry configuration supports registry blocking, mirroring and remapping rules.
    /// This field points to a registry configuration file, which can either be stored locally
    /// in the rootfs or retrieved from initdata.
    ///
    /// This value defaults to `None`.
    #[serde(default = "Option::default")]
    pub registry_config: Option<RegistryConfig>,

    /// The maximum number of layers downloaded concurrently when
    /// pulling one specific image.
    ///
    /// This defaults to [`DEFAULT_MAX_CONCURRENT_DOWNLOAD`].
    #[serde(default = "default_max_concurrent_layer_downloads_per_image")]
    pub max_concurrent_layer_downloads_per_image: usize,

    /// Proxy configuration for pulling images.
    #[serde(default = "Option::default")]
    pub image_pull_proxy: Option<ProxyConfig>,

    /// To pull an image from a registry with a self-signed ceritifcate,
    /// supply the corresponding trusted root cert (in PEM format) here.
    #[serde(default = "Vec::default")]
    pub extra_root_certificates: Vec<String>,

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
            default_snapshot: SnapshotType::default(),
            max_concurrent_layer_downloads_per_image: DEFAULT_MAX_CONCURRENT_DOWNLOAD,
            image_security_policy_uri: None,
            sigstore_config_uri: None,
            authenticated_registry_credentials_uri: None,
            registry_configuration_uri: None,
            registry_config: None,
            image_pull_proxy: None,
            extra_root_certificates: Vec::new(),

            #[cfg(feature = "keywrap-native")]
            kbc: default_kbc(),

            #[cfg(feature = "keywrap-native")]
            kbs_uri: default_kbs_uri(),
        }
    }
}

#[derive(PartialEq, Debug)]
struct KernelParameterConfigs {
    https_proxy: Option<String>,
    http_proxy: Option<String>,
    no_proxy: Option<String>,
    authenticated_registry_credentials_uri: Option<String>,
    image_security_policy_uri: Option<String>,
    enable_signature_verification: bool,
}

impl KernelParameterConfigs {
    fn new(kernel_cmdline: &str) -> Self {
        let cmdline: HashMap<&str, &str> = kernel_cmdline
            .split_ascii_whitespace()
            .filter_map(|s| s.split_once('='))
            .collect();

        Self {
            https_proxy: cmdline.get("agent.https_proxy").map(|s| s.to_string()),
            http_proxy: cmdline.get("agent.http_proxy").map(|s| s.to_string()),
            no_proxy: cmdline.get("agent.no_proxy").map(|s| s.to_string()),
            authenticated_registry_credentials_uri: cmdline
                .get("agent.image_registry_auth")
                .map(|s| s.to_string()),
            image_security_policy_uri: cmdline
                .get("agent.image_policy_file")
                .map(|s| s.to_string()),
            enable_signature_verification: cmdline
                .get("agent.enable_signature_verification")
                .map(|s| s.parse::<bool>().unwrap_or(false))
                .unwrap_or_default(),
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

        let image_config = serde_json::from_reader::<File, ImageConfig>(file)
            .context("failed to parse config file")?;
        Ok(image_config)
    }
}

impl ImageConfig {
    /// Try read configs from kernel command line, and other items will be set as default.
    pub fn from_kernel_cmdline() -> Self {
        let mut res = ImageConfig {
            work_dir: PathBuf::from(DEFAULT_WORK_DIR.to_string()),
            default_snapshot: SnapshotType::default(),
            max_concurrent_layer_downloads_per_image: DEFAULT_MAX_CONCURRENT_DOWNLOAD,
            image_security_policy_uri: None,
            sigstore_config_uri: None,
            authenticated_registry_credentials_uri: None,
            registry_configuration_uri: None,
            registry_config: None,
            image_pull_proxy: None,
            extra_root_certificates: Vec::new(),

            #[cfg(feature = "keywrap-native")]
            kbc: default_kbc(),

            #[cfg(feature = "keywrap-native")]
            kbs_uri: default_kbs_uri(),
        };

        if let Ok(kernel_cmdline) = fs::read_to_string("/proc/cmdline") {
            debug!("Try read image pull parameters from kernel cmdline");
            let parameters_from_kernel = KernelParameterConfigs::new(&kernel_cmdline);
            let image_pull_proxy = ProxyConfig {
                https_proxy: parameters_from_kernel.https_proxy,
                http_proxy: parameters_from_kernel.http_proxy,
                no_proxy: parameters_from_kernel.no_proxy,
            };

            res.authenticated_registry_credentials_uri =
                parameters_from_kernel.authenticated_registry_credentials_uri;
            if parameters_from_kernel.enable_signature_verification {
                res.image_security_policy_uri = parameters_from_kernel.image_security_policy_uri;
            }

            if image_pull_proxy.http_proxy.is_some()
                || image_pull_proxy.https_proxy.is_some()
                || image_pull_proxy.no_proxy.is_some()
            {
                res.image_pull_proxy = Some(image_pull_proxy);
            }
        }

        res
    }

    /// Construct an instance of `ImageConfig` with specific work directory.
    pub fn new(image_work_dir: PathBuf) -> Self {
        Self {
            work_dir: image_work_dir,
            ..Default::default()
        }
    }
}

#[cfg(feature = "snapshot-overlayfs")]
#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use std::io::prelude::*;

    #[rstest]
    #[case(
        "BOOT_IMAGE=/boot/vmlinuz-6.2.0-060200-generic root=UUID=f601123 ro vga=792 console=tty0 console=ttyS0,115200n8 agent.https_proxy=http://1.2.3.4:1234",
        KernelParameterConfigs {
            https_proxy: Some("http://1.2.3.4:1234".into()),
            http_proxy: None,
            no_proxy: None,
            authenticated_registry_credentials_uri: None,
            image_security_policy_uri: None,
            enable_signature_verification: false
        }
    )]
    #[case("
        BOOT_IMAGE=/boot/vmlinuz-6.2.0-060200-generic agent.no_proxy=localhost root=UUID=f601123 ro vga=792 console=tty0 console=ttyS0,115200n8 agent.https_proxy=http://1.2.3.4:1234",
        KernelParameterConfigs {
            https_proxy: Some("http://1.2.3.4:1234".into()),
            http_proxy: None,
            no_proxy: Some("localhost".into()),
            authenticated_registry_credentials_uri: None,
            image_security_policy_uri: None,
            enable_signature_verification: false
        }
    )]
    #[case("
        BOOT_IMAGE=/boot/vmlinuz-6.2.0-060200-generic agent.no_proxy=localhost   \n agent.image_registry_auth=kbs:///default/credentials/test root=UUID=f601123 ro vga=792 console=tty0 console=ttyS0,115200n8 agent.https_proxy=http://1.2.3.4:1234",
        KernelParameterConfigs {
            https_proxy: Some("http://1.2.3.4:1234".into()),
            http_proxy: None,
            no_proxy: Some("localhost".into()),
            authenticated_registry_credentials_uri: Some("kbs:///default/credentials/test".into()),
            image_security_policy_uri: None,
            enable_signature_verification: false
        }
    )]
    #[case("
        agent.no_proxy=localhost   \n agent.image_registry_auth=file:///root/.docker/config.json agent.https_proxy=http://1.2.3.4:1234",
        KernelParameterConfigs {
            https_proxy: Some("http://1.2.3.4:1234".into()),
            http_proxy: None,
            no_proxy: Some("localhost".into()),
            authenticated_registry_credentials_uri: Some("file:///root/.docker/config.json".into()),
            image_security_policy_uri: None,
            enable_signature_verification: false
        }
    )]
    #[case("
        BOOT_IMAGE=/boot/vmlinuz-6.2.0-060200-generic agent.no_proxy=localhost agent.image_policy_file=kbs:///default/image-policy/test  \n agent.image_registry_auth=kbs:///a/b/c root=UUID=f601123 ro vga=792 console=tty0 console=ttyS0,115200n8 agent.https_proxy=http://1.2.3.4:1234",
        KernelParameterConfigs {
            https_proxy: Some("http://1.2.3.4:1234".into()),
            http_proxy: None,
            no_proxy: Some("localhost".into()),
            authenticated_registry_credentials_uri: Some("kbs:///a/b/c".into()),
            image_security_policy_uri: Some("kbs:///default/image-policy/test".into()),
            enable_signature_verification: false
        }
    )]
    #[case("
        BOOT_IMAGE=/boot/vmlinuz-6.2.0-060200-generic agent.no_proxy=localhost agent.image_policy_file=file:///etc/image-policy.json  \n agent.image_registry_auth=kbs:///a/b/c root=UUID=f601123 ro vga=792 console=tty0 console=ttyS0,115200n8 agent.https_proxy=http://1.2.3.4:1234",
        KernelParameterConfigs {
            https_proxy: Some("http://1.2.3.4:1234".into()),
            http_proxy: None,
            no_proxy: Some("localhost".into()),
            authenticated_registry_credentials_uri: Some("kbs:///a/b/c".into()),
            image_security_policy_uri: Some("file:///etc/image-policy.json".into()),
            enable_signature_verification: false
        }
    )]
    #[case("
        agent.enable_signature_verification=true agent.no_proxy=localhost agent.image_policy_file=file:///etc/image-policy.json  \n agent.image_registry_auth=kbs:///a/b/c agent.https_proxy=http://1.2.3.4:1234",
        KernelParameterConfigs {
            https_proxy: Some("http://1.2.3.4:1234".into()),
            http_proxy: None,
            no_proxy: Some("localhost".into()),
            authenticated_registry_credentials_uri: Some("kbs:///a/b/c".into()),
            image_security_policy_uri: Some("file:///etc/image-policy.json".into()),
            enable_signature_verification: true
        }
    )]
    #[case("
        agent.enable_signature_verification=true agent.no_proxy=localhost agent.image_policy_file=file:///etc/image-policy.json  \n agent.image_registry_auth=kbs:///a/b/c agent.https_proxy=http://1.2.3.4:1234 agent.http_proxy=http://1.2.3.4:1234",
        KernelParameterConfigs {
            https_proxy: Some("http://1.2.3.4:1234".into()),
            http_proxy: Some("http://1.2.3.4:1234".into()),
            no_proxy: Some("localhost".into()),
            authenticated_registry_credentials_uri: Some("kbs:///a/b/c".into()),
            image_security_policy_uri: Some("file:///etc/image-policy.json".into()),
            enable_signature_verification: true
        }
    )]
    fn test_parse_kernel_parameter(
        #[case] kernel_parameter: &str,
        #[case] expected: KernelParameterConfigs,
    ) {
        let config = KernelParameterConfigs::new(kernel_parameter);
        assert_eq!(config, expected);
    }

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
            "work_dir": "/run/kata-containers/image/",
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
}
