// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{env, fs, path::Path};

use anyhow::*;
use attestation_agent::config::aa_kbc_params::AaKbcParams;
use config::{Config, File};
use image_rs::config::ImageConfig;
use serde::Deserialize;
use tracing::{debug, info};

cfg_if::cfg_if! {
    if #[cfg(feature = "ttrpc")] {
        const DEFAULT_CDH_SOCKET_ADDR: &str = "unix:///run/confidential-containers/cdh.sock";
    } else {
        const DEFAULT_CDH_SOCKET_ADDR: &str = "127.0.0.1:50000";
    }
}

const CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS: &str =
    "CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS";

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

    pub socket: String,

    /// Sealed Secrets use JWS integrity protection to ensure
    /// that the secret cannot be modified while it is stored
    /// by the untrusted control plane.
    /// If needed, this check can be skipped.
    /// The integrity protection applies only to the sealed secret
    /// itself, not to the unsealed secret.
    #[serde(default)]
    pub skip_sealed_secret_verification: bool,
}

impl CdhConfig {
    pub fn new(config_path: Option<String>) -> Result<Self> {
        let config_path = config_path.or_else(|| {
            if let std::result::Result::Ok(env_path) = env::var("CDH_CONFIG_PATH") {
                debug!("Read CDH's config path from env: {env_path}");
                return Some(env_path);
            }
            None
        });

        let mut config = match config_path {
            Some(path) => {
                info!("Use configuration file {path}");
                if !Path::new(&path).exists() {
                    bail!("Config file {path} not found.")
                }

                Self::from_file(&path)?
            }
            None => {
                info!("No config path specified, use a default config (some parts will read from kernel cmdline).");
                Self {
                    kbc: KbsConfig::new()?,
                    credentials: Vec::new(),
                    socket: DEFAULT_CDH_SOCKET_ADDR.into(),
                    image: ImageConfig::from_kernel_cmdline(),
                    skip_sealed_secret_verification: false,
                }
            }
        };

        if let std::result::Result::Ok(env) =
            env::var(CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS)
        {
            info!("Read authenticated registry credentials URI from env: {env}");
            config.image.authenticated_registry_credentials_uri = Some(env);
        }

        config.extend_credentials_from_kernel_cmdline()?;
        Ok(config)
    }

    /// Load `CdhConfig` from a configuration file. Supported formats are all formats supported by the
    /// `config` crate.
    fn from_file(config_path: &str) -> Result<Self> {
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
    fn extend_credentials_from_kernel_cmdline(&mut self) -> Result<()> {
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
    use std::{env, io::Write};

    use anyhow::anyhow;
    use image_rs::{
        config::{ImageConfig, ProxyConfig},
        registry::{Config, Mirror, Registry},
    };
    use rstest::rstest;
    use serial_test::serial;

    use crate::{config::DEFAULT_CDH_SOCKET_ADDR, CdhConfig, KbsConfig};

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
[kbc]
name = "offline_fs_kbc"

[image]
some_undefined_field = "unknown value"
"#,
    Some(CdhConfig {
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

    #[test]
    #[serial]
    fn test_config_path() {
        // --config takes precedence,
        // then env.CDH_CONFIG_PATH

        let config = CdhConfig::new(None).expect("Must be successful");
        let expected = CdhConfig {
            kbc: KbsConfig {
                name: "offline_fs_kbc".into(),
                url: "".into(),
                kbs_cert: None,
            },
            credentials: Vec::new(),
            socket: DEFAULT_CDH_SOCKET_ADDR.into(),
            image: ImageConfig::from_kernel_cmdline(),
            skip_sealed_secret_verification: false,
        };
        assert_eq!(config, expected);

        let config = CdhConfig::new(Some("/thing".into())).unwrap_err();
        let expected = anyhow!("Config file /thing not found.");
        assert_eq!(format!("{config}"), format!("{expected}"));

        env::set_var("CDH_CONFIG_PATH", "/byenv");
        let config = CdhConfig::new(None).unwrap_err();
        let expected = anyhow!("Config file /byenv not found.");
        assert_eq!(format!("{config}"), format!("{expected}"));
        env::remove_var("CDH_CONFIG_PATH");

        let config = CdhConfig::new(Some("/thing".into())).unwrap_err();
        let expected = anyhow!("Config file /thing not found.");
        assert_eq!(format!("{config}"), format!("{expected}"));
    }

    #[test]
    #[serial]
    fn test_config_auth_override_by_env() {
        let config = r#"
[kbc]
name = "offline_fs_kbc"

[image]
authenticated_registry_credentials_uri = "kbs:///default/auth/1"
        "#;
        let mut file = tempfile::Builder::new()
            .append(true)
            .suffix(".toml")
            .tempfile()
            .unwrap();
        file.write_all(config.as_bytes()).unwrap();

        // without env and from config file
        let config_path = file.path().to_str().unwrap().to_string();
        let config = CdhConfig::new(Some(config_path.clone())).expect("Must be successful");
        assert_eq!(
            config.image.authenticated_registry_credentials_uri,
            Some("kbs:///default/auth/1".into())
        );

        // overrided by env
        env::set_var(
            "CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS",
            "file:///test",
        );
        let config = CdhConfig::new(Some(config_path.clone())).unwrap();
        assert_eq!(
            config.image.authenticated_registry_credentials_uri,
            Some("file:///test".to_string())
        );
        env::remove_var("CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS");

        // no env again
        let config = CdhConfig::new(Some(config_path)).unwrap();
        assert_eq!(
            config.image.authenticated_registry_credentials_uri,
            Some("kbs:///default/auth/1".into())
        );
    }
}
