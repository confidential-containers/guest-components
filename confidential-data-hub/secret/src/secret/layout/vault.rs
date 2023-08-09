// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use kms::ProviderSettings;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub use kms::Annotations;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct VaultSecret {
    /// The id of this secret
    pub name: String,

    /// decryptor driver of the secret
    pub provider: String,

    /// extra information to create a client
    pub provider_settings: ProviderSettings,

    /// Other fields used to fetch the secret
    pub annotations: Annotations,
}

impl VaultSecret {
    pub(crate) async fn unseal(&self) -> Result<Vec<u8>> {
        let mut provider = kms::new_getter(&self.provider, self.provider_settings.clone())
            .await
            .map_err(|e| Error::UnsealVaultFailed(format!("create provider failed: {e}")))?;
        let secret = provider
            .get_secret(&self.name, &self.annotations)
            .await
            .map_err(|e| {
                Error::UnsealVaultFailed(format!("get secret from provider failed: {e}"))
            })?;
        Ok(secret)
    }
}
