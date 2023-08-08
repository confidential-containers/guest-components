// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub use kms::Annotations;

use base64::{engine::general_purpose::STANDARD, Engine};
use crypto::WrapType;
use kms::ProviderSettings;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// An Envelope is a secret encrypted by digital envelope mechanism.
/// It can be described as
///
/// {Enc(KMS, DEK), Enc(DEK, secret), paras...}
///
/// where Enc(A,B) means use key A to encrypt B
///
/// The fields inside this Struct will be flattened in a Secret wrapper.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Envelope {
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

impl Envelope {
    pub(crate) async fn unseal(&self) -> Result<Vec<u8>> {
        // get encryption key
        let enc_dek = STANDARD.decode(&self.encrypted_key).map_err(|e| {
            Error::UnsealEnvelopeFailed(format!("base64 decode encrypted_key failed: {e}"))
        })?;
        let mut provider = kms::new_decryptor(&self.provider, self.provider_settings.clone())
            .await
            .map_err(|e| Error::UnsealEnvelopeFailed(format!("create provider failed: {e}")))?;
        let dek = Zeroizing::new(
            provider
                .decrypt(&enc_dek, &self.key_id, &self.annotations)
                .await
                .map_err(|e| {
                    Error::UnsealEnvelopeFailed(format!("decrypt encryption key failed: {e}"))
                })?,
        );

        // get plaintext of secret
        let iv = STANDARD
            .decode(&self.iv)
            .map_err(|e| Error::UnsealEnvelopeFailed(format!("base64 decode iv failed: {e}")))?;
        let encrypted_data = STANDARD.decode(&self.encrypted_data).map_err(|e| {
            Error::UnsealEnvelopeFailed(format!("base64 decode encrypted_data failed: {e}"))
        })?;
        let plaintext = crypto::decrypt(dek, encrypted_data, iv, self.wrap_type.clone())
            .map_err(|e| Error::UnsealEnvelopeFailed(format!("decrypt envelope failed: {e}")))?;
        Ok(plaintext)
    }
}
