// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use anyhow::Result;

use kbs_types::HashAlgorithm;
use serde::Deserialize;

/// Initdata defined in
/// <https://github.com/confidential-containers/trustee/blob/47d7a2338e0be76308ac19be5c0c172c592780aa/kbs/docs/initdata.md>
#[derive(Deserialize)]
pub struct Initdata {
    pub version: String,
    pub algorithm: HashAlgorithm,
    pub data: HashMap<String, String>,
}

impl Initdata {
    /// Create a new Initdata instance from a TOML string.
    pub fn parse_and_get_digest(toml: &str) -> Result<(Self, Vec<u8>)> {
        let initdata: Initdata = toml::de::from_str(toml)?;
        let digest = initdata.algorithm.digest(toml.as_bytes());
        Ok((initdata, digest))
    }
}
