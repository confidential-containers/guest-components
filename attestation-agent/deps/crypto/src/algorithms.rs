// Copyright (c) 2024 Alibaba Cloud
// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fmt;
use std::str::FromStr;

/// Hash algorithms used to calculate runtime/init data binding
#[derive(Serialize, Deserialize, Clone, Debug, Display, Copy)]
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

    /// Return a list of all supported hash algorithms.
    pub fn list_all() -> Vec<Self> {
        vec![
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
        ]
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseHashAlgorithmError;

// XXX: Required to allow conversion to a std::error::Error by `anyhow!()`.
impl fmt::Display for ParseHashAlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ParseHashAlgorithmError")
    }
}

impl FromStr for HashAlgorithm {
    type Err = ParseHashAlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cleaned = s.replace('-', "").to_lowercase();

        let result = match cleaned.as_str() {
            "sha256" => HashAlgorithm::Sha256,
            "sha384" => HashAlgorithm::Sha384,
            "sha512" => HashAlgorithm::Sha512,
            _ => return Err(ParseHashAlgorithmError),
        };

        Ok(result)
    }
}
