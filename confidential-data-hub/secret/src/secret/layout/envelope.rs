// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub use kms::Annotations;

use base64::{engine::general_purpose::STANDARD, Engine};
use crypto::WrapType;
use kms::ProviderSettings;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, EnvelopeError>;

#[derive(Error, Debug)]
pub enum EnvelopeError {
    #[error("base64 decoding failed when {context}")]
    Base64DecodeFailed {
        #[source]
        source: base64::DecodeError,
        context: &'static str,
    },

    #[error("kms interface when {context}")]
    KmsError {
        #[source]
        source: kms::Error,
        context: &'static str,
    },

    #[error("decrypt envelope")]
    Decrypt(#[from] anyhow::Error),
}

/// An Envelope Secret is a secret encrypted by digital envelope mechanism.
/// It can be described as
///
/// {Enc(KMS, DEK), Enc(DEK, secret), paras...}
///
/// where Enc(A,B) means use key A to encrypt B
///
/// The fields inside this Struct will be flattened in a Secret wrapper.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct EnvelopeSecret {
    /// key id to locate the key inside KMS
    pub key_id: String,

    /// Encrypted DEK by key inside KMS
    pub encrypted_key: String,

    /// Encrypted data (secret) by DEK
    pub encrypted_data: String,

    /// Encryption scheme of the Encrypted data by DEK
    pub wrap_type: WrapType,

    /// IV of encrypted_data, if used
    pub iv: String,

    /// decryptor driver of the secret
    pub provider: String,

    /// extra information to create a client
    pub provider_settings: ProviderSettings,

    /// KMS specific fields to locate the Key inside KMS
    pub annotations: Annotations,
}

impl EnvelopeSecret {
    pub(crate) async fn unseal(&self) -> Result<Vec<u8>> {
        // get encryption key
        let enc_dek = STANDARD.decode(&self.encrypted_key).map_err(|e| {
            EnvelopeError::Base64DecodeFailed {
                context: "decode `encrypted_key`",
                source: e,
            }
        })?;
        let mut provider = kms::new_decryptor(&self.provider, self.provider_settings.clone())
            .await
            .map_err(|e| EnvelopeError::KmsError {
                context: "create KMS provider",
                source: e,
            })?;
        let dek = Zeroizing::new(
            provider
                .decrypt(&enc_dek, &self.key_id, &self.annotations)
                .await
                .map_err(|e| EnvelopeError::KmsError {
                    context: "decrypt encryption key",
                    source: e,
                })?,
        );

        // get plaintext of secret
        let iv = STANDARD
            .decode(&self.iv)
            .map_err(|e| EnvelopeError::Base64DecodeFailed {
                context: "decode iv",
                source: e,
            })?;
        let encrypted_data = STANDARD.decode(&self.encrypted_data).map_err(|e| {
            EnvelopeError::Base64DecodeFailed {
                context: "decode encrypted_data",
                source: e,
            }
        })?;
        let plaintext = crypto::decrypt(dek, encrypted_data, iv, self.wrap_type.clone())?;
        Ok(plaintext)
    }
}
