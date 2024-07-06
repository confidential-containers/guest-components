// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use serde::Deserialize;

pub mod aa_kbc_params;

#[cfg(feature = "coco_as")]
pub mod coco_as;

#[cfg(feature = "kbs")]
pub mod kbs;

pub const DEFAULT_AA_CONFIG_PATH: &str = "/etc/attestation-agent.conf";

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// configs about token
    pub token_configs: TokenConfigs,
    // TODO: Add more fields that accessing AS needs.
    #[serde(default)]
    pub attester: AttesterConfig,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct AttesterConfig {
    /// The default register index to use in `extend_runtime_measurement`
    /// operations.
    pub default_register_index: Option<u64>,
}

impl Config {
    pub fn new() -> Result<Self> {
        Ok(Self {
            token_configs: TokenConfigs::new()?,
            attester: AttesterConfig::default(),
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TokenConfigs {
    /// This config item is used when `coco_as` feature is enabled.
    #[cfg(feature = "coco_as")]
    pub coco_as: coco_as::CoCoASConfig,

    /// This config item is used when `kbs` feature is enabled.
    #[cfg(feature = "kbs")]
    pub kbs: kbs::KbsConfig,
}

impl TokenConfigs {
    pub fn new() -> Result<Self> {
        Ok(Self {
            #[cfg(feature = "coco_as")]
            coco_as: coco_as::CoCoASConfig::new()?,

            #[cfg(feature = "kbs")]
            kbs: kbs::KbsConfig::new()?,
        })
    }
}

impl TryFrom<&str> for Config {
    type Error = config::ConfigError;
    fn try_from(config_path: &str) -> Result<Self, Self::Error> {
        let c = config::Config::builder()
            .add_source(config::File::with_name(config_path))
            .build()?;

        let cfg = c.try_deserialize()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "kbs", feature = "coco_as"))]
    #[rstest::rstest]
    #[case("config.example.toml")]
    #[case("config.example.json")]
    fn parse_config(#[case] config: &str) {
        let _config = super::Config::try_from(config).expect("failed to parse config file");
    }

    #[test]
    fn parse_attester_config() {
        let config_str = "config.example.toml";
        let config = super::Config::try_from(config_str).expect("failed to parse config file");
        assert_eq!(config.attester.default_register_index, Some(42));
        let config_str = "config.example.json";
        let config = super::Config::try_from(config_str).expect("failed to parse config file");
        assert!(config.attester.default_register_index.is_none());
    }
}
