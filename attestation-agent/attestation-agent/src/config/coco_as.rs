// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::Deserialize;

use super::aa_kbc_params;

#[derive(Clone, Debug, Deserialize)]
pub struct CoCoASConfig {
    /// URL Address of Attestation Service.
    pub url: String,
}

impl Default for CoCoASConfig {
    fn default() -> Self {
        let aa_kbc_params = aa_kbc_params::get_params().expect("failed to get aa_kbc_params");
        Self {
            url: aa_kbc_params.uri.clone(),
        }
    }
}
