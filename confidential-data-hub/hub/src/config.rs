// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{env, fs, path::Path};

use anyhow::*;
use attestation_agent::config::aa_kbc_params::AaKbcParams;
use config::{Config, File};
use log::{debug, info};
use serde::Deserialize;

cfg_if::cfg_if! {
    if #[cfg(feature = "ttrpc")] {
        const DEFAULT_CDH_SOCKET_ADDR: &str = "unix:///run/confidential-containers/cdh.sock";
    } else {
        const DEFAULT_CDH_SOCKET_ADDR: &str = "127.0.0.1:50000";
    }
}

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

#[derive(Clone, Deserialize, Debug, PartialEq, Default)]
pub struct ImageConfiguration {
    /// If any image security policy would be used to control the image pulling
    /// like signature verification, this field is used to set the URI of the
    /// policy file.
    ///
    /// Now it supports two different forms:
    /// - `KBS URI`: the iamge security policy will be fetched from KBS.
    ///     e.g. [`image_rs::config::POLICY_FILE_PATH`]
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
    pub image_security_policy_uri: Option<String>,

    /// Sigstore config file URI for simple signing scheme.
    ///
    /// When `image_security_policy_uri` is set and `SimpleSigning` (signedBy) is
    /// used in the policy, the signatures of the images would be used for image
    /// signature validation. This policy will record where the signatures is.
    ///
    /// Now it supports two different forms:
    /// - `KBS URI`: the sigstore config file will be fetched from KBS,
    ///     e.g. [`image_rs::config::SIG_STORE_CONFIG_DEFAULT_FILE`].
    /// - `Local Path`: the sigstore config file will be fetched from somewhere locally,
    ///     e.g. `file:///etc/simple-signing.yaml`.
    ///
    /// This value defaults to `None`.
    pub sigstore_config_uri: Option<String>,

    /// If any credential auth (Base) would be used to connect to download
    /// image from private registry, this field is used to set the URI of the
    /// credential file.
    ///
    /// Now it supports two different forms:
    /// - `KBS URI`: the registry auth will be fetched from KBS,
    ///     e.g. [`image_rs::config::AUTH_FILE_PATH`].
    /// - `Local Path`: the registry auth will be fetched from somewhere locally,
    ///     e.g. `file:///etc/image-registry-auth.json`.
    ///
    /// This value defaults to `None`.
    pub authenticated_registry_credentials_uri: Option<String>,

    /// The maximum number of layers downloaded concurrently when
    /// pulling one specific image.
    ///
    /// This defaults to [`image_rs::config::DEFAULT_MAX_CONCURRENT_DOWNLOAD`].
    pub max_concurrent_layer_downloads_per_image: Option<usize>,

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

    /// The path to store the pulled image layer data.
    ///
    /// This value defaults to [`image_rs::config::DEFAULT_WORK_DIR`].
    pub work_dir: Option<String>,
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
pub struct CdhConfig {
    pub kbc: KbsConfig,

    #[serde(default)]
    pub credentials: Vec<Credential>,

    #[serde(default)]
    pub image: ImageConfiguration,

    pub socket: String,
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
                info!("No config path specified, use a default config.");
                Self {
                    kbc: KbsConfig::new()?,
                    credentials: Vec::new(),
                    socket: DEFAULT_CDH_SOCKET_ADDR.into(),
                    image: ImageConfiguration::default(),
                }
            }
        };

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
    /// `/run/confidential-containers/cdh` or it will be treated as dangerous
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
    }
}

#[cfg(test)]
mod tests {
    use std::{env, io::Write};

    use anyhow::anyhow;
    use rstest::rstest;

    use crate::{config::DEFAULT_CDH_SOCKET_ADDR, CdhConfig, ImageConfiguration, KbsConfig};

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
    "#,
        Some(CdhConfig {
            kbc: KbsConfig {
                name: "offline_fs_kbc".to_string(),
                url: "".to_string(),
                kbs_cert: Some("".to_string()),
            },
            credentials: vec![],
            image: ImageConfiguration {
                max_concurrent_layer_downloads_per_image: Some(3),
                sigstore_config_uri: Some("kbs:///default/sigstore-config/test".to_string()),
                image_security_policy_uri: Some("kbs:///default/security-policy/test".to_string()),
                authenticated_registry_credentials_uri: Some("kbs:///default/credential/test".to_string()),
                image_pull_proxy: None,
                skip_proxy_ips: None,
                work_dir: None,
            },
            socket: "unix:///run/confidential-containers/cdh.sock".to_string(),
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
        image: ImageConfiguration {
            max_concurrent_layer_downloads_per_image: None,
                sigstore_config_uri: None,
                image_security_policy_uri: None,
                authenticated_registry_credentials_uri: None,
                image_pull_proxy: None,
                skip_proxy_ips: None,
                work_dir: None,
        },
        socket: DEFAULT_CDH_SOCKET_ADDR.to_string(),
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
        image: ImageConfiguration {
            max_concurrent_layer_downloads_per_image: None,
                sigstore_config_uri: None,
                image_security_policy_uri: None,
                authenticated_registry_credentials_uri: None,
                image_pull_proxy: None,
                skip_proxy_ips: None,
                work_dir: None,
        },
        socket: DEFAULT_CDH_SOCKET_ADDR.to_string(),
    })
    )]
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
            image: crate::ImageConfiguration::default(),
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
}
