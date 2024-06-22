// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, Default)]
pub struct KbsConfig {
    /// URL Address of KBS.
    pub url: String,

    /// Cert of KBS
    pub cert: Option<String>,
}
