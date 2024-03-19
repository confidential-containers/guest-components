// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::env;

use anyhow::*;
use config::{Config, File};
use log::{debug, warn};
use serde::Deserialize;
use tokio::fs;

const DEFAULT_CDH_SOCKET_ADDR: &str = "unix:///run/confidential-containers/cdh.sock";

#[derive(Deserialize, Debug)]
pub struct KbsConfig {
    pub name: String,

    pub url: String,

    pub kbs_cert: Option<String>,
}

impl Default for KbsConfig {
    fn default() -> Self {
        Self {
            name: "offline_fs_kbc".into(),
            url: "null".into(),
            kbs_cert: None,
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct Credential {
    pub resource_uri: String,
    pub path: String,
}

#[derive(Deserialize, Debug)]
pub struct CdhConfig {
    pub kbc: KbsConfig,

    pub credentials: Vec<Credential>,

    pub socket: String,
}

impl Default for CdhConfig {
    fn default() -> Self {
        Self {
            socket: DEFAULT_CDH_SOCKET_ADDR.into(),
            kbc: KbsConfig::default(),
            credentials: Vec::default(),
        }
    }
}

impl CdhConfig {
    pub async fn init(config_path: &str) -> Result<Self> {
        let mut config = Self::from_file(config_path).unwrap_or_else(|e| {
            warn!("read config file {config_path} failed {e:?}, use a default config where `aa_kbc_params` = offline_fs_kbc::null.");
            Self::default()
        });

        config.update_from_kernel_cmdline().await?;
        Ok(config)
    }

    /// Load `CdhConfig` from a configuration file. Supported formats are all formats supported by the
    /// `config` crate.
    fn from_file(config_path: &str) -> Result<Self> {
        let c = Config::builder()
            .set_default("socket", DEFAULT_CDH_SOCKET_ADDR)?
            .add_source(File::with_name(config_path))
            .build()?;

        let res = c.try_deserialize().context("invalid config").unwrap();
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
    async fn update_from_kernel_cmdline(&mut self) -> Result<()> {
        let cmdline = fs::read_to_string("/proc/cmdline")
            .await
            .context("read kernel cmdline failed")?;
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
        if let Err(_) = attestation_agent::config::aa_kbc_params::get_value() {
            debug!("No aa_kbc_params provided in kernel cmdline, env and peerpod config.");
            // KBS configurations
            env::set_var(
                "AA_KBC_PARAMS",
                format!("{}::{}", self.kbc.name, self.kbc.url),
            );
        }

        if let Some(kbs_cert) = &self.kbc.kbs_cert {
            env::set_var("KBS_CERT", kbs_cert);
        }
    }
}
