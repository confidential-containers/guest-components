// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};

/// Serialized [`crate::Annotations`]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AliAnnotations {
    pub iv: String,
}

/// Serialized [`crate::ProviderSettings`]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AliProviderSettings {
    pub client_key_id: String,
    pub kms_instance_id: String,
}
