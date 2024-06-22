// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, Default)]
pub struct CoCoASConfig {
    /// URL Address of Attestation Service.
    pub url: String,
}
