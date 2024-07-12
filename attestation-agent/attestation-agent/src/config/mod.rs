// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Default PCR index used by AA. `17` is selected for its usage of dynamic root of trust for measurement.
/// - [Linux TPM PCR Registry](https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/)
/// - [TCG TRUSTED BOOT CHAIN IN EDK II](https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html)
const DEFAULT_PCR_INDEX: u64 = 17;

pub mod aa_kbc_params;

#[cfg(feature = "coco_as")]
pub mod coco_as;

#[cfg(feature = "kbs")]
pub mod kbs;

pub const DEFAULT_AA_CONFIG_PATH: &str = "/etc/attestation-agent.conf";

pub const DEFAULT_EVENTLOG_HASH: &str = "sha384";

/// Hash algorithms used to calculate runtime/init data binding
#[derive(Deserialize, Clone, Debug, Copy)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Sha384
    }
}

fn hash_reportdata<D: Digest>(material: &[u8]) -> Vec<u8> {
    D::new().chain_update(material).finalize().to_vec()
}

impl HashAlgorithm {
    pub fn digest(&self, material: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha256 => hash_reportdata::<Sha256>(material),
            HashAlgorithm::Sha384 => hash_reportdata::<Sha384>(material),
            HashAlgorithm::Sha512 => hash_reportdata::<Sha512>(material),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// configs about token
    pub token_configs: TokenConfigs,

    /// configs about eventlog
    pub eventlog_config: EventlogConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EventlogConfig {
    /// Hash algorithm used to extend runtime measurement for eventlog.
    pub eventlog_algorithm: HashAlgorithm,

    /// PCR Register to extend INIT entry
    pub init_pcr: u64,
}

impl Default for EventlogConfig {
    fn default() -> Self {
        Self {
            eventlog_algorithm: HashAlgorithm::Sha384,
            init_pcr: DEFAULT_PCR_INDEX,
        }
    }
}

impl Config {
    pub fn new() -> Result<Self> {
        Ok(Self {
            token_configs: TokenConfigs::new()?,
            eventlog_config: EventlogConfig::default(),
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
            .set_default("eventlog_config.eventlog_algorithm", DEFAULT_EVENTLOG_HASH)?
            .set_default("eventlog_config.init_pcr", DEFAULT_PCR_INDEX)?
            .build()?;

        let cfg = c.try_deserialize()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    #[rstest::rstest]
    #[case("config.example.toml")]
    #[case("config.example.json")]
    fn parse_config(#[case] config: &str) {
        let _config = super::Config::try_from(config).expect("failed to parse config file");
    }
}
