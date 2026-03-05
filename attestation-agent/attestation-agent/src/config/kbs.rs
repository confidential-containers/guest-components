// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Result};
use serde::Deserialize;

use super::aa_kbc_params::AaKbcParams;

#[derive(Clone, Debug, Deserialize, PartialEq, Default)]
pub enum TeeKeyAlgorithm {
    #[default]
    #[serde(rename = "ECDH-ES+A256KW-P256")]
    EcdhEsA256KwP256,
    #[serde(rename = "ECDH-ES+A256KW-P521")]
    EcdhEsA256KwP521,
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,
}

impl From<TeeKeyAlgorithm> for kbs_protocol::TeeKeyAlgorithm {
    fn from(value: TeeKeyAlgorithm) -> Self {
        match value {
            TeeKeyAlgorithm::EcdhEsA256KwP256 => Self::EcEcdhEsA256KwP256,
            TeeKeyAlgorithm::EcdhEsA256KwP521 => Self::EcEcdhEsA256KwP521,
            TeeKeyAlgorithm::RsaOaep256 => Self::RsaOaep256,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct KbsConfig {
    /// URL Address of KBS.
    pub url: String,

    /// Cert of KBS
    pub cert: Option<String>,

    #[serde(default)]
    pub tee_key_algorithm: TeeKeyAlgorithm,
}

#[cfg(test)]
mod tests {
    use super::TeeKeyAlgorithm;

    #[test]
    fn deserialize_jwa_compact_algorithms() {
        let p256: TeeKeyAlgorithm = serde_json::from_str("\"ECDH-ES+A256KW-P256\"")
            .expect("ECDH-ES+A256KW-P256 algorithm should parse");
        assert_eq!(p256, TeeKeyAlgorithm::EcdhEsA256KwP256);

        let p521: TeeKeyAlgorithm = serde_json::from_str("\"ECDH-ES+A256KW-P521\"")
            .expect("ECDH-ES+A256KW-P521 algorithm should parse");
        assert_eq!(p521, TeeKeyAlgorithm::EcdhEsA256KwP521);

        let rsa_oaep256: TeeKeyAlgorithm =
            serde_json::from_str("\"RSA-OAEP-256\"").expect("RSA-OAEP-256 algorithm should parse");
        assert_eq!(rsa_oaep256, TeeKeyAlgorithm::RsaOaep256);
    }
}

impl KbsConfig {
    /// This function will try to read kbc and url from aa_kbc_params from env and kernel commandline.
    /// If not given, or the kbc is not cc_kbc, it will return an error.
    /// Because only cc_kbc will set kbs uri.
    pub fn new() -> Result<Self> {
        let aa_kbc_params = AaKbcParams::new()?;
        if aa_kbc_params.kbc != "cc_kbc" {
            bail!("specified aa_kbc_params.kbc is not kbs");
        }
        Ok(Self {
            url: aa_kbc_params.uri,
            cert: None,
            tee_key_algorithm: TeeKeyAlgorithm::default(),
        })
    }
}
