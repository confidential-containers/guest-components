// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};

pub use kms::Annotations;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct VaultSecret {
    /// The id of this secret
    pub name: String,

    /// decryptor driver of the secret
    pub provider: String,

    /// Other fields used to fetch the secret
    pub annotations: Annotations,
}
