// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{env, fs};

use anyhow::*;
use attestation_agent::config::aa_kbc_params::AaKbcParams;
use config::{Config, File};
use image_rs::config::ImageConfig;
use serde::Deserialize;
use tracing::debug;

cfg_if::cfg_if! {
    if #[cfg(feature = "ttrpc")] {
        pub const DEFAULT_CDH_SOCKET_ADDR: &str = "unix:///run/confidential-containers/cdh.sock";
    } else {
        pub const DEFAULT_CDH_SOCKET_ADDR: &str = "127.0.0.1:50000";
    }
}

pub const DEFAULT_LOG_LEVEL: &str = "info";

#[derive(Clone, Deserialize, Debug, PartialEq)]
pub struct KbsConfig {
    pub name: String,

    pub url: String,

    pub kbs_cert: Option<String>,
}

impl KbsConfig {
    fn new() -> Result<Self> {
        debug!("Try to get kbc and url from env and kernel commandline.");
        let aa_kbc_params =
            AaKbcParams::new().context("failed to read aa_kbc_params to initialize KbsConfig")?;
        Ok(KbsConfig {
            name: aa_kbc_params.kbc,
            url: aa_kbc_params.uri,
            kbs_cert: None,
        })
    }
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
pub struct Credential {
    pub resource_uri: String,
    pub path: String,
}

fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.to_string()
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
pub struct LogConfig {
    /// log level
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: DEFAULT_LOG_LEVEL.to_string(),
        }
    }
}

fn default_socket_addr() -> String {
    DEFAULT_CDH_SOCKET_ADDR.to_string()
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
pub struct CdhConfig {
    pub kbc: KbsConfig,

    #[serde(default)]
    pub credentials: Vec<Credential>,

    /// Image pull configuration. Note that if `[image]` section is not given,
    /// the image pull configuration will be read from kernel commandline together
    /// with default values.
    #[serde(default = "ImageConfig::from_kernel_cmdline")]
    pub image: ImageConfig,

    /// socket address
    #[serde(default = "default_socket_addr")]
    pub socket: String,

    /// Sealed Secrets use JWS integrity protection to ensure
    /// that the secret cannot be modified while it is stored
    /// by the untrusted control plane.
    /// If needed, this check can be skipped.
    /// The integrity protection applies only to the sealed secret
    /// itself, not to the unsealed secret.
    #[serde(default)]
    pub skip_sealed_secret_verification: bool,

    /// log configuration
    #[serde(default)]
    pub log: LogConfig,
}

impl CdhConfig {
    pub fn default_with_kernel_cmdline() -> Result<Self> {
        Ok(Self {
            kbc: KbsConfig::new()?,
            credentials: Vec::new(),
            socket: default_socket_addr(),
            image: ImageConfig::from_kernel_cmdline(),
            skip_sealed_secret_verification: false,
            log: LogConfig::default(),
        })
    }

    /// Load `CdhConfig` from a configuration file. Supported formats are all formats supported by the
    /// `config` crate.
    pub fn from_file(config_path: &str) -> Result<Self> {
        let c = Config::builder()
            .set_default("socket", DEFAULT_CDH_SOCKET_ADDR)?
            .set_default("kbc.url", "")?
            .add_source(File::with_name(config_path))
            .build()?;

        let res = c.try_deserialize().context("invalid config")?;
        Ok(res)
    }

    /// all the resource ids can be from the kernel commandline in the following format:
    /// ```shell
    /// cdh.kbs_resources=<resource id 1>::<target path 1>,<resource id 2>::<target path 2>...
    /// ```
    ///
    /// for example
    /// ```shell
    /// cdh.kbs_resources=kbs:///default/key/1::/run/temp1,kbs:///default/key/2::/run/temp2
    /// ```
    ///
    /// It is supposed that all the `target path` should be with prefix
    /// `/run/confidential-containers/cdh/kbs` or it will be treated as dangerous
    /// path.
    ///
    /// TODO: delete this way after initdata mechanism could cover CDH's launch config.
    pub fn extend_credentials_from_kernel_cmdline(&mut self) -> Result<()> {
        let cmdline = fs::read_to_string("/proc/cmdline").context("read kernel cmdline failed")?;
        let kbs_resources = cmdline
            .split_ascii_whitespace()
            .find(|para| para.starts_with("cdh.kbs_resources="))
            .unwrap_or("cdh.kbs_resources=")
            .strip_prefix("cdh.kbs_resources=")
            .expect("must have one")
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|it| it.split_once("::"))
            .map(|it| Credential {
                resource_uri: it.0.to_owned(),
                path: it.1.to_owned(),
            });

        self.credentials.extend(kbs_resources);
        Ok(())
    }
}

impl CdhConfig {
    pub fn set_configuration_envs(&self) {
        if env::var("AA_KBC_PARAMS").is_err() {
            env::set_var(
                "AA_KBC_PARAMS",
                format!("{}::{}", self.kbc.name, self.kbc.url),
            );
        }
        // KBS configurations
        if let Some(kbs_cert) = &self.kbc.kbs_cert {
            env::set_var("KBS_CERT", kbs_cert);
        }

        if self.skip_sealed_secret_verification {
            env::set_var("SKIP_SEALED_SECRET_VERIFICATION", "true");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use image_rs::{
        config::{ImageConfig, ProxyConfig},
        registry::{Config, Mirror, Registry},
    };
    use rstest::rstest;
    use serial_test::serial;

    use crate::{config::DEFAULT_CDH_SOCKET_ADDR, CdhConfig, KbsConfig, LogConfig};

    #[rstest]
    #[case(
        r#"
socket = "unix:///run/confidential-containers/cdh.sock"

[kbc]
name = "offline_fs_kbc"
url = ""
kbs_cert = ""

[image]
max_concurrent_layer_downloads_per_image = 3
sigstore_config_uri = "kbs:///default/sigstore-config/test"
image_security_policy_uri = "kbs:///default/security-policy/test"
authenticated_registry_credentials_uri = "kbs:///default/credential/test"
extra_root_certificates = ["cert1", "cert2"]

[image.registry_config]
unqualified-search-registries = ["docker.io", "example1.com"]

[[image.registry_config.registry]]
prefix = "example.com/foo"
insecure = false
blocked = false
location = "internal-registry-for-example.com/bar"

[[image.registry_config.registry.mirror]]
location = "example-mirror-0.local/mirror-for-foo"

[image.image_pull_proxy]
https_proxy = "http://127.0.0.1:8080"
    "#,
        Some(CdhConfig {
            log: LogConfig::default(),
            kbc: KbsConfig {
                name: "offline_fs_kbc".to_string(),
                url: "".to_string(),
                kbs_cert: Some("".to_string()),
            },
            credentials: vec![],
            image: ImageConfig {
                max_concurrent_layer_downloads_per_image: 3,
                sigstore_config_uri: Some("kbs:///default/sigstore-config/test".to_string()),
                image_security_policy_uri: Some("kbs:///default/security-policy/test".to_string()),
                authenticated_registry_credentials_uri: Some("kbs:///default/credential/test".to_string()),
                registry_config: Some(Config {
                    unqualified_search_registries: vec!["docker.io".to_string(), "example1.com".to_string()],
                    registry: vec![
                        Registry {
                            prefix: "example.com/foo".to_string(),
                            insecure: false,
                            blocked: false,
                            location: "internal-registry-for-example.com/bar".to_string(),
                            mirror: vec![
                                Mirror {
                                    location: "example-mirror-0.local/mirror-for-foo".to_string(),
                                    insecure: false, //default
                                }
                            ],
                        }
                    ],
                }),
                image_pull_proxy: Some(ProxyConfig {
                    https_proxy: Some("http://127.0.0.1:8080".into()),
                    http_proxy: None,
                    no_proxy: None,
                }),
                extra_root_certificates: vec!["cert1".into(), "cert2".into()],
                ..Default::default()
            },
            socket: "unix:///run/confidential-containers/cdh.sock".to_string(),
            skip_sealed_secret_verification: false,
        })
    )]
    #[case(
        r#"
socket = "unix:///run/confidential-containers/cdh.sock"

[kbc]
name = "offline_fs_kbc"
url = ""
kbs_cert = ""

[[credentials]]
    "#,
        None
    )]
    #[case(
        r#"
[kbc]
name = "offline_fs_kbc"
"#,
    Some(CdhConfig {
        log: LogConfig::default(),
        kbc: KbsConfig {
            name: "offline_fs_kbc".to_string(),
            url: "".to_string(),
            kbs_cert: None,
        },
        credentials: vec![],
        image: ImageConfig {
                sigstore_config_uri: None,
                image_security_policy_uri: None,
                authenticated_registry_credentials_uri: None,
                image_pull_proxy: None,
                ..Default::default()
        },
        socket: DEFAULT_CDH_SOCKET_ADDR.to_string(),
        skip_sealed_secret_verification: false,
    })
    )]
    #[case(
        r#"
[log]
level = "warn"

[kbc]
name = "offline_fs_kbc"

[image]
some_undefined_field = "unknown value"
"#,
    Some(CdhConfig {
        log: LogConfig {
            level: "warn".to_string(),
        },
        kbc: KbsConfig {
            name: "offline_fs_kbc".to_string(),
            url: "".to_string(),
            kbs_cert: None,
        },
        credentials: vec![],
        image: ImageConfig {
                sigstore_config_uri: None,
                image_security_policy_uri: None,
                authenticated_registry_credentials_uri: None,
                image_pull_proxy: None,
                ..Default::default()
        },
        socket: DEFAULT_CDH_SOCKET_ADDR.to_string(),
        skip_sealed_secret_verification: false,
    })
    )]
    #[serial]
    fn read_config(#[case] config: &str, #[case] expected: Option<CdhConfig>) {
        let mut file = tempfile::Builder::new()
            .append(true)
            .suffix(".toml")
            .tempfile()
            .unwrap();
        file.write_all(config.as_bytes()).unwrap();
        let res = CdhConfig::from_file(file.path().to_str().unwrap());
        match expected {
            Some(cfg) => assert_eq!(cfg, res.unwrap()),
            None => assert!(res.is_err()),
        }
    }
}
