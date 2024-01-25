// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use serde::Deserialize;
use std::fs::File;
use thiserror::Error;

pub mod aa_kbc_params;

pub const DEFAULT_AA_CONFIG_PATH: &str = "/etc/attestation-agent.toml";

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
pub struct Config {
    /// URL Address of Attestation Service
    pub as_uri: String,
    // TODO: Add more fields that accessing AS needs.
}

#[derive(Error, Debug)]
pub enum ConfigFileError {
    #[error("failed to open")]
    Io(#[from] std::io::Error),
    #[error("failed to parse")]
    Parse(#[from] serde_json::Error),
}

impl TryFrom<&str> for Config {
    type Error = ConfigFileError;
    fn try_from(config_path: &str) -> Result<Self, Self::Error> {
        let file = File::open(config_path)?;
        let cfg: Config = serde_json::from_reader(file)?;
        Ok(cfg)
    }
}
