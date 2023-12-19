// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};

/// Serialized [`crate::Annotations`]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AliCryptAnnotations {
    pub iv: String,
}

/// Serialized [`crate::Annotations`]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AliSecretAnnotations {
    pub version_stage: String,
    pub version_id: String,
}

/// Serialized [`crate::ProviderSettings`]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AliProviderSettings {
    pub client_key_id: String,
    pub kms_instance_id: String,
}
