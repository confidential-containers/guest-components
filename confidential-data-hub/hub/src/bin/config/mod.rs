// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{env, fs, path::Path};

use anyhow::*;
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

#[derive(Deserialize, Debug, PartialEq)]
pub struct KbsConfig {
    pub name: String,

    pub url: String,

    pub kbs_cert: Option<String>,
}

impl Default for KbsConfig {
    fn default() -> Self {
        debug!("Try to get kbc and url from env and kernel commandline.");
        match attestation_agent::config::aa_kbc_params::get_params() {
            std::result::Result::Ok(aa_kbc_params) => KbsConfig {
                name: aa_kbc_params.kbc,
                url: aa_kbc_params.uri,
                kbs_cert: None,
            },
            Err(_) => {
                debug!("Failed to get aa_kbc_params from env or kernel cmdline. Use offline_fs_kbc by default.");
                KbsConfig {
                    name: "offline_fs_kbc".into(),
                    url: "".into(),
                    kbs_cert: None,
                }
            }
        }
    }
}

impl KbsConfig {
    fn new() -> Result<Self> {
        debug!("Try to get kbc and url from env and kernel commandline.");
        let aa_kbc_params = attestation_agent::config::aa_kbc_params::get_params()?;
        Ok(Self {
            name: aa_kbc_params.kbc,
            url: aa_kbc_params.uri,
            kbs_cert: None,
        })
    }
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct Credential {
    pub resource_uri: String,
    pub path: String,
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct CdhConfig {
    pub kbc: KbsConfig,

    #[serde(default)]
    pub credentials: Vec<Credential>,

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

        if let Some(path) = &config_path {
            if !Path::new(&path).exists() {
                bail!("Config file {path} not found.")
            }

            return Self::from_file(path);
        }

        info!("No config path specified");
        debug!("Attempt to get configuration from aa_kbc_params.");
        let mut config = Self {
            socket: DEFAULT_CDH_SOCKET_ADDR.into(),
            kbc: KbsConfig::new()?,
            credentials: Vec::default(),
        };

        config.extend_credentials_from_kernel_cmdline()?;
        Ok(config)
    }

    /// Load `CdhConfig` from a configuration file. Supported formats are all formats supported by the
    /// `config` crate.
    fn from_file(config_path: &str) -> Result<Self> {
        let c = Config::builder()
            .set_default("socket", DEFAULT_CDH_SOCKET_ADDR)?
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

    use crate::{config::DEFAULT_CDH_SOCKET_ADDR, CdhConfig, KbsConfig};

    #[rstest]
    #[case(
        r#"
socket = "unix:///run/confidential-containers/cdh.sock"

[kbc]
name = "offline_fs_kbc"
url = ""
kbs_cert = ""
    "#,
        true
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
        false
    )]
    #[case(
        r#"
socket = "unix:///run/confidential-containers/cdh.sock"

[kbc]
name = "offline_fs_kbc"
url = ""
kbs_cert = ""

[[credentials]]
resource_uri = "kbs:///default/1/1"
path = "/run/confidential-containers/cdh/kms-credential/aliyun/config.toml"
    "#,
        true
    )]
    fn read_config(#[case] config: &str, #[case] successful: bool) {
        let mut file = tempfile::Builder::new()
            .append(true)
            .suffix(".toml")
            .tempfile()
            .unwrap();
        file.write_all(config.as_bytes()).unwrap();
        let res = CdhConfig::from_file(file.path().to_str().unwrap());
        assert_eq!(res.is_ok(), successful, "{res:?}");
    }

    #[test]
    fn test_config_path() {
        // --config takes precedence,
        // then env.CDH_CONFIG_PATH

        let config = CdhConfig::new(None).expect("Must be successful");
        let expected = CdhConfig {
            kbc: KbsConfig {
                name: "offline_fs_kbc".into(),
                url: "null".into(),
                kbs_cert: None,
            },
            credentials: Vec::new(),
            socket: DEFAULT_CDH_SOCKET_ADDR.into(),
        };
        assert_eq!(config, expected);

        let config = CdhConfig::new(Some("/thing".into())).unwrap_err();
        let expected = anyhow!("Config file /thing not found.");
        assert_eq!(format!("{config}"), format!("{expected}"));

        env::set_var("CDH_CONFIG_PATH", "/byenv");
        let config = CdhConfig::new(None).unwrap_err();
        let expected = anyhow!("Config file /byenv not found.");
        assert_eq!(format!("{config}"), format!("{expected}"));

        let config = CdhConfig::new(Some("/thing".into())).unwrap_err();
        let expected = anyhow!("Config file /thing not found.");
        assert_eq!(format!("{config}"), format!("{expected}"));
    }
}
