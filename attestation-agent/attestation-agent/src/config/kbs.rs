// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use serde::Deserialize;

use super::aa_kbc_params::AaKbcParams;

#[derive(Clone, Debug, Deserialize)]
pub struct KbsConfig {
    /// URL Address of KBS.
    pub url: String,

    /// Cert of KBS
    pub cert: Option<String>,
}

impl KbsConfig {
    pub fn new() -> Result<Self> {
        let aa_kbc_params = AaKbcParams::new()?;
        Ok(Self {
            url: aa_kbc_params.uri,
            cert: None,
        })
    }
}
