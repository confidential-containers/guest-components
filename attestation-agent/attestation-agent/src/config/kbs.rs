// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Result};
use serde::Deserialize;

use super::aa_kbc_params::AaKbcParams;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct KbsConfig {
    /// URL Address of KBS.
    pub url: String,

    /// Cert of KBS
    pub cert: Option<String>,
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
        })
    }
}
