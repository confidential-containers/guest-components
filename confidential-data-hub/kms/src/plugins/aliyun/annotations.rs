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
    pub version_stage: String,
    pub version_id: String,
}
