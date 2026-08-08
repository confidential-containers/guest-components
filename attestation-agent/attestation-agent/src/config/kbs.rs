// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Result};
use serde::Deserialize;

use super::aa_kbc_params::AaKbcParams;

use kbs_protocol::TeeKeyAlgorithm;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct KbsConfig {
    /// URL Address of KBS.
    pub url: String,

    /// Cert of KBS
    pub cert: Option<String>,

    #[serde(default)]
    pub tee_key_algorithm: TeeKeyAlgorithm,

    /// The hint that KBS resolves to the attestation policies that evaluate this
    /// guest's evidence. The accepted values are specific to a KBS
    /// deployment, so this has to be agreed with the KBS administrator.
    ///
    /// Empty by default, which leaves the policy selection to KBS. An empty
    /// policy_selector is not sent, because KBS rejects a policy_selector it does not know.
    #[serde(default)]
    pub policy_selector: String,
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
            policy_selector: String::new(),
        })
    }
}
