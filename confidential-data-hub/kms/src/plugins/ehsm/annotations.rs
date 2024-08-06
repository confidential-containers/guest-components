// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};

/// Serialized [`crate::ProviderSettings`]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EhsmProviderSettings {
    pub app_id: String,
    pub endpoint: String,
}
