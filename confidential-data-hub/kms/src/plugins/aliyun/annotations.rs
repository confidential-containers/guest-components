// Copyright (c) 2024 Alibaba Cloud
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
    // set to empty string to get newest version of secret
    #[serde(default)]
    pub version_stage: String,

    // set to empty string to get newest version of secret
    #[serde(default)]
    pub version_id: String,
}
