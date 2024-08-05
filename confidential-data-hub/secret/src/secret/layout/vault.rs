// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use kms::ProviderSettings;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use kms::Annotations;

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("kms interface when {context}")]
    KmsError {
        #[source]
        source: kms::Error,
        context: &'static str,
    },
}

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
        let provider = kms::new_getter(&self.provider, self.provider_settings.clone())
            .await
            .map_err(|e| VaultError::KmsError {
                context: "create kms provider",
                source: e,
            })?;

        let secret = provider
            .get_secret(&self.name, &self.annotations)
            .await
            .map_err(|e| VaultError::KmsError {
                context: "get secret from provider",
                source: e,
            })?;

        Ok(secret)
    }
}
