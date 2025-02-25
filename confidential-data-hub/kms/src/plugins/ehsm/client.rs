// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::env;

use ehsm_client::{api::KMS, client::EHSMClient};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use const_format::concatcp;
use log::info;
use serde_json::Value;
use tokio::fs;

use crate::plugins::_IN_GUEST_DEFAULT_KEY_PATH;
use crate::{Annotations, Decrypter, Encrypter, ProviderSettings};
use crate::{Error, Result};

use super::annotations::EhsmProviderSettings;
use super::credential::Credential;

pub struct EhsmKmsClient {
    client: EHSMClient,
}

const EHSM_IN_GUEST_DEFAULT_KEY_PATH: &str = concatcp!(_IN_GUEST_DEFAULT_KEY_PATH, "/ehsm");

impl EhsmKmsClient {
    pub fn new(app_id: &str, api_key: &str, endpoint: &str) -> Result<Self> {
        Ok(Self {
            client: EHSMClient {
                base_url: endpoint.to_owned(),
                appid: app_id.to_owned(),
                apikey: api_key.to_owned(),
            },
        })
    }

    /// build client with parameters that have been exported to environment.
    pub fn new_from_env() -> Result<Self> {
        Ok(Self {
            client: EHSMClient::new(),
        })
    }

    /// This new function is used by a in-pod client. The side-effect is to read the
    /// [`EHSM_IN_GUEST_DEFAULT_KEY_PATH`] which is the by default path where the credential
    /// to access kms is saved.
    pub async fn from_provider_settings(provider_settings: &ProviderSettings) -> Result<Self> {
        let key_path =
            env::var("EHSM_IN_GUEST_KEY_PATH").unwrap_or(EHSM_IN_GUEST_DEFAULT_KEY_PATH.to_owned());
        info!("EHSM_IN_GUEST_KEY_PATH = {}", key_path);

        let provider_settings: EhsmProviderSettings =
            serde_json::from_value(Value::Object(provider_settings.clone())).map_err(|e| {
                Error::EhsmKmsError(format!("parse provider setting failed: {e:?}"))
            })?;

        let credential_path = format!("{}/credential_{}.json", key_path, provider_settings.app_id);

        let api_key = {
            let cred = fs::read_to_string(credential_path)
                .await
                .map_err(|e| Error::EhsmKmsError(format!("read credential failed: {e:?}")))?;
            let cred: Credential = serde_json::from_str(&cred)
                .map_err(|e| Error::EhsmKmsError(format!("serialize credential failed: {e:?}")))?;
            cred.api_key
        };

        Self::new(
            &provider_settings.app_id,
            &api_key,
            &provider_settings.endpoint,
        )
    }

    /// Export the [`ProviderSettings`] of the current client. This function is to be used
    /// in the encryptor side. The [`ProviderSettings`] will be used to initial a client
    /// in the decryptor side.
    pub fn export_provider_settings(&self) -> Result<ProviderSettings> {
        let provider_settings = EhsmProviderSettings {
            app_id: self.client.appid.clone(),
            endpoint: self.client.base_url.clone(),
        };

        let provider_settings = serde_json::to_value(provider_settings)
            .map_err(|e| Error::EhsmKmsError(format!("serialize ProviderSettings failed: {e:?}")))?
            .as_object()
            .expect("must be an object")
            .to_owned();

        Ok(provider_settings)
    }
}

#[async_trait]
impl Encrypter for EhsmKmsClient {
    async fn encrypt(&mut self, data: &[u8], key_id: &str) -> Result<(Vec<u8>, Annotations)> {
        let ciphertext = self
            .client
            .encrypt(key_id, &STANDARD.encode(data), None)
            .await
            .map_err(|e| Error::EhsmKmsError(format!("EHSM-KMS encrypt failed: {e:?}")))?;

        let annotations = Annotations::new();

        Ok((ciphertext.into(), annotations))
    }
}

#[async_trait]
impl Decrypter for EhsmKmsClient {
    async fn decrypt(
        &mut self,
        ciphertext: &[u8],
        key_id: &str,
        _annotations: &Annotations,
    ) -> Result<Vec<u8>> {
        let plaintext_b64 = self
            .client
            .decrypt(
                key_id,
                std::str::from_utf8(ciphertext).map_err(|e| {
                    Error::EhsmKmsError(format!("decrypt &[u8] to &str failed: {e:?}"))
                })?,
                None,
            )
            .await
            .map_err(|e| Error::EhsmKmsError(format!("EHSM-KMS decrypt failed: {e:?}")))?;
        let plaintext = STANDARD.decode(plaintext_b64).map_err(|e| {
            Error::EhsmKmsError(format!("decode plaintext for decryption failed: {e:?}"))
        })?;

        Ok(plaintext)
    }
}

impl EhsmKmsClient {
    pub async fn create_key(&mut self, key_spec: &str) -> Result<String> {
        let origin = "EH_INTERNAL_KEY";
        let keyusage = "EH_KEYUSAGE_ENCRYPT_DECRYPT";
        let key_id = self
            .client
            .create_key(key_spec, origin, keyusage)
            .await
            .map_err(|e| Error::EhsmKmsError(format!("EHSM-KMS create key failed: {e:?}")))?;

        Ok(key_id)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use crate::{plugins::ehsm::client::EhsmKmsClient, Decrypter, Encrypter};

    #[ignore]
    #[tokio::test]
    async fn test_create_key() {
        let key_spec = "EH_AES_GCM_256";
        let provider_settings = json!({
            "app_id": "86f0e9fe-****-a224ddee1233",
            "endpoint": "https://172.0.0.1:9000",
        });

        // init client at user side
        let provider_settings = provider_settings.as_object().unwrap().to_owned();
        let mut client = EhsmKmsClient::from_provider_settings(&provider_settings)
            .await
            .unwrap();

        // create key
        let key_id = client.create_key(key_spec).await;

        assert!(key_id.is_ok());
    }

    #[rstest]
    #[ignore]
    #[case(b"this is a test plaintext")]
    #[ignore]
    #[case(b"this is a another test plaintext")]
    #[tokio::test]
    async fn key_lifetime(#[case] plaintext: &[u8]) {
        let key_spec = "EH_AES_GCM_256";
        let provider_settings = json!({
            "app_id": "86f0e9fe-7f05-4110-9f65-a224ddee1233",
            "endpoint": "https://172.16.1.1:9002",
        });

        // init client at user side
        let provider_settings = provider_settings.as_object().unwrap().to_owned();
        let mut client = EhsmKmsClient::from_provider_settings(&provider_settings)
            .await
            .unwrap();

        // create key
        let key_id = client.create_key(key_spec).await.unwrap();

        let mut encryptor = EhsmKmsClient::from_provider_settings(&provider_settings)
            .await
            .unwrap();

        println!("{}", key_id);

        // do encryption
        let (ciphertext, secret_settings) = encryptor
            .encrypt(plaintext, &key_id)
            .await
            .expect("encrypt");
        let provider_settings = encryptor.export_provider_settings().unwrap();

        // init decrypter in a guest
        let mut decryptor = EhsmKmsClient::from_provider_settings(&provider_settings)
            .await
            .unwrap();

        // do decryption
        let decrypted = decryptor
            .decrypt(&ciphertext, &key_id, &secret_settings)
            .await
            .expect("decrypt");

        assert_eq!(decrypted, plaintext);
    }
}
