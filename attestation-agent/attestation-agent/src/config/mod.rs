// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use crypto::HashAlgorithm;
use serde::Deserialize;

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

#[derive(Clone, Debug, Deserialize, PartialEq, Default)]
pub struct Config {
    /// configs about token
    #[serde(default)]
    pub token_configs: TokenConfigs,

    /// configs about eventlog
    pub eventlog_config: EventlogConfig,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct EventlogConfig {
    /// Hash algorithm used to extend runtime measurement for eventlog.
    pub eventlog_algorithm: HashAlgorithm,

    /// PCR Register to extend INIT entry
    pub init_pcr: u64,

    /// Flag whether enable eventlog recording
    pub enable_eventlog: bool,
}

impl Default for EventlogConfig {
    fn default() -> Self {
        Self {
            eventlog_algorithm: HashAlgorithm::Sha384,
            init_pcr: DEFAULT_PCR_INDEX,
            enable_eventlog: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct TokenConfigs {
    /// This config item is used when `coco_as` feature is enabled.
    #[cfg(feature = "coco_as")]
    pub coco_as: Option<coco_as::CoCoASConfig>,

    /// This config item is used when `kbs` feature is enabled.
    #[cfg(feature = "kbs")]
    pub kbs: Option<kbs::KbsConfig>,
}

impl Default for TokenConfigs {
    fn default() -> Self {
        #[cfg(feature = "kbs")]
        let kbs = kbs::KbsConfig::new().ok();

        Self {
            #[cfg(feature = "coco_as")]
            coco_as: None,
            #[cfg(feature = "kbs")]
            kbs,
        }
    }
}

impl TryFrom<&str> for Config {
    type Error = config::ConfigError;
    fn try_from(config_path: &str) -> Result<Self, Self::Error> {
        let c = config::Config::builder()
            .add_source(config::File::with_name(config_path))
            .set_default("eventlog_config.eventlog_algorithm", DEFAULT_EVENTLOG_HASH)?
            .set_default("eventlog_config.init_pcr", DEFAULT_PCR_INDEX)?
            .set_default("eventlog_config.enable_eventlog", "false")?
            .build()?;

        let cfg = c.try_deserialize()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use crypto::HashAlgorithm;

    use crate::config::{EventlogConfig, TokenConfigs};

    use super::Config;

    #[rstest::rstest]
    #[case("config.example.toml",
    Config {
        token_configs: TokenConfigs {
            #[cfg(feature = "coco_as")]
            coco_as: Some(crate::config::coco_as::CoCoASConfig {
                url: "http://127.0.0.1:8000".to_string(),
            }),
            #[cfg(feature = "kbs")]
            kbs: Some(crate::config::kbs::KbsConfig {
                url: "https://127.0.0.1:8080".to_string(),
                cert: Some("-----BEGIN CERTIFICATE-----
MIIDljCCAn6gAwIBAgIUR/UNh13GFam4emgludtype/S9BIwDQYJKoZIhvcNAQEL
BQAwdTELMAkGA1UEBhMCQ04xETAPBgNVBAgMCFpoZWppYW5nMREwDwYDVQQHDAhI
YW5nemhvdTERMA8GA1UECgwIQUFTLVRFU1QxFDASBgNVBAsMC0RldmVsb3BtZW50
MRcwFQYDVQQDDA5BQVMtVEVTVC1IVFRQUzAeFw0yNDAzMTgwNzAzNTNaFw0yNTAz
MTgwNzAzNTNaMHUxCzAJBgNVBAYTAkNOMREwDwYDVQQIDAhaaGVqaWFuZzERMA8G
A1UEBwwISGFuZ3pob3UxETAPBgNVBAoMCEFBUy1URVNUMRQwEgYDVQQLDAtEZXZl
bG9wbWVudDEXMBUGA1UEAwwOQUFTLVRFU1QtSFRUUFMwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDfp1aBr6LiNRBlJUcDGcAbcUCPG6UzywtVIc8+comS
ay//gwz2AkDmFVvqwI4bdp/NUCwSC6ShHzxsrCEiagRKtA3af/ckM7hOkb4S6u/5
ewHHFcL6YOUp+NOH5/dSLrFHLjet0dt4LkyNBPe7mKAyCJXfiX3wb25wIBB0Tfa0
p5VoKzwWeDQBx7aX8TKbG6/FZIiOXGZdl24DGARiqE3XifX7DH9iVZ2V2RL9+3WY
05GETNFPKtcrNwTy8St8/HsWVxjAzGFzf75Lbys9Ff3JMDsg9zQzgcJJzYWisxlY
g3CmnbENP0eoHS4WjQlTUyY0mtnOwodo4Vdf8ZOkU4wJAgMBAAGjHjAcMBoGA1Ud
EQQTMBGCCWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAKW32spii
t2JB7C1IvYpJw5mQ5bhIlldE0iB5rwWvNbuDgPrgfTI4xiX5sumdHw+P2+GU9KXF
nWkFRZ9W/26xFrVgGIS/a07aI7xrlp0Oj+1uO91UhCL3HhME/0tPC6z1iaFeZp8Y
T1tLnafqiGiThFUgvg6PKt86enX60vGaTY7sslRlgbDr9sAi/NDSS7U1PviuC6yo
yJi7BDiRSx7KrMGLscQ+AKKo2RF1MLzlJMa1kIZfvKDBXFzRd61K5IjDRQ4HQhwX
DYEbQvoZIkUTc1gBUWDcAUS5ztbJg9LCb9WVtvUTqTP2lGuNymOvdsuXq+sAZh9b
M9QaC1mzQ/OStg==
-----END CERTIFICATE-----
".to_string()),
            })
        },
        eventlog_config: EventlogConfig {
            eventlog_algorithm: HashAlgorithm::Sha384,
            init_pcr: 17,
            enable_eventlog: false,
        }
    })]
    #[case("config.example.json",
    Config {
        token_configs: TokenConfigs {
            #[cfg(feature = "coco_as")]
            coco_as: Some(crate::config::coco_as::CoCoASConfig {
                url: "http://127.0.0.1:8000".to_string(),
            }),
            #[cfg(feature = "kbs")]
            kbs: Some(crate::config::kbs::KbsConfig {
                url: "https://127.0.0.1:8080".to_string(),
                cert: Some("-----BEGIN CERTIFICATE-----
MIIDljCCAn6gAwIBAgIUR/UNh13GFam4emgludtype/S9BIwDQYJKoZIhvcNAQEL
BQAwdTELMAkGA1UEBhMCQ04xETAPBgNVBAgMCFpoZWppYW5nMREwDwYDVQQHDAhI
YW5nemhvdTERMA8GA1UECgwIQUFTLVRFU1QxFDASBgNVBAsMC0RldmVsb3BtZW50
MRcwFQYDVQQDDA5BQVMtVEVTVC1IVFRQUzAeFw0yNDAzMTgwNzAzNTNaFw0yNTAz
MTgwNzAzNTNaMHUxCzAJBgNVBAYTAkNOMREwDwYDVQQIDAhaaGVqaWFuZzERMA8G
A1UEBwwISGFuZ3pob3UxETAPBgNVBAoMCEFBUy1URVNUMRQwEgYDVQQLDAtEZXZl
bG9wbWVudDEXMBUGA1UEAwwOQUFTLVRFU1QtSFRUUFMwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDfp1aBr6LiNRBlJUcDGcAbcUCPG6UzywtVIc8+comS
ay//gwz2AkDmFVvqwI4bdp/NUCwSC6ShHzxsrCEiagRKtA3af/ckM7hOkb4S6u/5
ewHHFcL6YOUp+NOH5/dSLrFHLjet0dt4LkyNBPe7mKAyCJXfiX3wb25wIBB0Tfa0
p5VoKzwWeDQBx7aX8TKbG6/FZIiOXGZdl24DGARiqE3XifX7DH9iVZ2V2RL9+3WY
05GETNFPKtcrNwTy8St8/HsWVxjAzGFzf75Lbys9Ff3JMDsg9zQzgcJJzYWisxlY
g3CmnbENP0eoHS4WjQlTUyY0mtnOwodo4Vdf8ZOkU4wJAgMBAAGjHjAcMBoGA1Ud
EQQTMBGCCWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAKW32spii
t2JB7C1IvYpJw5mQ5bhIlldE0iB5rwWvNbuDgPrgfTI4xiX5sumdHw+P2+GU9KXF
nWkFRZ9W/26xFrVgGIS/a07aI7xrlp0Oj+1uO91UhCL3HhME/0tPC6z1iaFeZp8Y
T1tLnafqiGiThFUgvg6PKt86enX60vGaTY7sslRlgbDr9sAi/NDSS7U1PviuC6yo
yJi7BDiRSx7KrMGLscQ+AKKo2RF1MLzlJMa1kIZfvKDBXFzRd61K5IjDRQ4HQhwX
DYEbQvoZIkUTc1gBUWDcAUS5ztbJg9LCb9WVtvUTqTP2lGuNymOvdsuXq+sAZh9b
M9QaC1mzQ/OStg==
-----END CERTIFICATE-----
".to_string()),
            })
        },
        eventlog_config: EventlogConfig {
            eventlog_algorithm: HashAlgorithm::Sha384,
            init_pcr: 17,
            enable_eventlog: false,
        }
    })]
    #[case(
    "test/config1.toml",
    Config {
        token_configs: TokenConfigs {
            #[cfg(feature = "coco_as")]
            coco_as: Some(crate::config::coco_as::CoCoASConfig {
                url: "http://127.0.0.1:8000".to_string(),
            }),
            #[cfg(feature = "kbs")]
            kbs: Some(crate::config::kbs::KbsConfig {
                url: "https://127.0.0.1:8080".to_string(),
                cert: Some("cert".to_string()),
            })
        },
        eventlog_config: EventlogConfig {
            eventlog_algorithm: HashAlgorithm::Sha384,
            init_pcr: 17,
            enable_eventlog: false,
        }
    })]
    #[case(
    "test/config2.toml",
    Config {
        token_configs: TokenConfigs {
            #[cfg(feature = "coco_as")]
            coco_as: None,
            #[cfg(feature = "kbs")]
            kbs: Some(crate::config::kbs::KbsConfig {
                url: "https://127.0.0.1:8080".to_string(),
                cert: Some("cert".to_string()),
            })
        },
        eventlog_config: EventlogConfig {
            eventlog_algorithm: HashAlgorithm::Sha384,
            init_pcr: 17,
            enable_eventlog: false,
        }
    })]
    #[case(
    "test/config3.toml", 
    Config {
        token_configs: TokenConfigs {
            #[cfg(feature = "coco_as")]
            coco_as: Some(crate::config::coco_as::CoCoASConfig {
                url: "http://127.0.0.1:8000".to_string(),
            }),
            #[cfg(feature = "kbs")]
            kbs: Some(crate::config::kbs::KbsConfig {
                url: "https://127.0.0.1:8080".to_string(),
                cert: None,
            })
        },
        eventlog_config: EventlogConfig {
            eventlog_algorithm: HashAlgorithm::Sha384,
            init_pcr: 17,
            enable_eventlog: false,
        }
    })]
    #[case(
    "test/config4.toml", 
    Config {
        token_configs: TokenConfigs {
            #[cfg(feature = "coco_as")]
            coco_as: None,
            #[cfg(feature = "kbs")]
            kbs: None,
        },
        eventlog_config: EventlogConfig {
            eventlog_algorithm: HashAlgorithm::Sha384,
            init_pcr: 17,
            enable_eventlog: false,
        }
    })]
    #[case(
    "test/config5.toml", 
    Config {
        token_configs: TokenConfigs {
            #[cfg(feature = "coco_as")]
            coco_as: None,
            #[cfg(feature = "kbs")]
            kbs: None,
        },
        eventlog_config: EventlogConfig {
            eventlog_algorithm: HashAlgorithm::Sha384,
            init_pcr: 17,
            enable_eventlog: false,
        }
    })]
    #[case(
        "test/config6.toml", 
        Config {
            token_configs: TokenConfigs {
                #[cfg(feature = "coco_as")]
                coco_as: None,
                #[cfg(feature = "kbs")]
                kbs: None,
            },
            eventlog_config: EventlogConfig {
                eventlog_algorithm: HashAlgorithm::Sha384,
                init_pcr: 17,
                enable_eventlog: false,
            }
        })]
    fn parse_configs(#[case] config: &str, #[case] expected: Config) {
        let _config = Config::try_from(config).expect("failed to parse config file");
        assert_eq!(_config, expected);
    }
}
