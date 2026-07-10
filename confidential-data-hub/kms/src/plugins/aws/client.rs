// Copyright (c) 2026 Confidential Containers Authors
//
// SPDX-License-Identifier: Apache-2.0
//

use std::env;

use async_trait::async_trait;
use aws_sdk_kms::{
    config::{BehaviorVersion, Credentials, Region},
    primitives::Blob,
    Client as KmsClient,
};
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use const_format::concatcp;
use serde_json::Value;
use tokio::fs;
use tracing::info;

use crate::plugins::_IN_GUEST_DEFAULT_KEY_PATH;
use crate::{Annotations, Decrypter, Encrypter, Getter, ProviderSettings, Setter};
use crate::{Error, Result};

use super::annotations::{AwsCryptAnnotations, AwsProviderSettings, AwsSecretAnnotations};
use super::credential::AwsCredential;

/// Default in-guest directory holding the AWS credential file. The credential is
/// expected to be provisioned into the TEE's encrypted memory before use.
const AWS_IN_GUEST_DEFAULT_KEY_PATH: &str = concatcp!(_IN_GUEST_DEFAULT_KEY_PATH, "/aws");

/// Name of the credential file inside the key path. Unlike Aliyun/eHSM the AWS
/// credential is not keyed on any public identifier (the decryptor side only
/// knows the region), so a fixed file name is used.
const AWS_CREDENTIAL_FILE_NAME: &str = "credential.json";

/// A client that talks to AWS KMS (for envelope secrets) and AWS Secrets Manager
/// (for vault secrets) using a single set of static IAM credentials.
#[derive(Clone, Debug)]
pub struct AwsKmsClient {
    region: String,
    kms: KmsClient,
    secrets_manager: SecretsManagerClient,
}

impl AwsKmsClient {
    /// Build a client from a region and explicit static credentials. This is the
    /// entry point used on the user/encryptor side (e.g. by `secret_cli`).
    pub fn new(
        region: &str,
        access_key_id: &str,
        secret_access_key: &str,
        session_token: Option<&str>,
    ) -> Result<Self> {
        let credentials = Credentials::new(
            access_key_id.to_owned(),
            secret_access_key.to_owned(),
            session_token.map(ToOwned::to_owned),
            None,
            "cdh-aws-static",
        );

        let region = region.to_owned();

        let kms_config = aws_sdk_kms::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region.clone()))
            .credentials_provider(credentials.clone())
            .build();

        let secrets_manager_config = aws_sdk_secretsmanager::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region.clone()))
            .credentials_provider(credentials)
            .build();

        Ok(Self {
            region,
            kms: KmsClient::from_conf(kms_config),
            secrets_manager: SecretsManagerClient::from_conf(secrets_manager_config),
        })
    }

    pub async fn from_provider_settings(provider_settings: &ProviderSettings) -> Result<Self> {
        let key_path =
            env::var("AWS_IN_GUEST_KEY_PATH").unwrap_or(AWS_IN_GUEST_DEFAULT_KEY_PATH.to_owned());
        info!("AWS_IN_GUEST_KEY_PATH = {key_path}");

        let provider_settings: AwsProviderSettings =
            serde_json::from_value(Value::Object(provider_settings.clone()))
                .map_err(|e| Error::AwsKmsError(format!("parse provider setting failed: {e:?}")))?;

        let credential_path = format!("{key_path}/{AWS_CREDENTIAL_FILE_NAME}");
        let credential = fs::read_to_string(&credential_path).await.map_err(|e| {
            Error::AwsKmsError(format!(
                "read credential file {credential_path} failed: {e:?}"
            ))
        })?;
        let credential: AwsCredential = serde_json::from_str(&credential)
            .map_err(|e| Error::AwsKmsError(format!("parse credential failed: {e:?}")))?;

        Self::new(
            &provider_settings.region,
            &credential.access_key_id,
            &credential.secret_access_key,
            credential.session_token.as_deref(),
        )
    }

    /// Export the [`ProviderSettings`] of the current client. This function is to
    /// be used on the encryptor side. The [`ProviderSettings`] will be used to
    /// initialize a client on the decryptor side.
    pub fn export_provider_settings(&self) -> Result<ProviderSettings> {
        let provider_settings = AwsProviderSettings {
            region: self.region.clone(),
        };

        let provider_settings = serde_json::to_value(provider_settings)
            .map_err(|e| Error::AwsKmsError(format!("serialize ProviderSettings failed: {e:?}")))?
            .as_object()
            .expect("must be an object")
            .to_owned();

        Ok(provider_settings)
    }
}

#[async_trait]
impl Encrypter for AwsKmsClient {
    async fn encrypt(&mut self, data: &[u8], key_id: &str) -> Result<(Vec<u8>, Annotations)> {
        let response = self
            .kms
            .encrypt()
            .key_id(key_id)
            .plaintext(Blob::new(data.to_vec()))
            .send()
            .await
            .map_err(|e| Error::AwsKmsError(format!("AWS KMS encrypt failed: {e:?}")))?;

        let ciphertext = response
            .ciphertext_blob
            .ok_or_else(|| Error::AwsKmsError("AWS KMS encrypt returned no ciphertext".into()))?
            .into_inner();

        // AWS KMS embeds the IV/nonce in the returned ciphertext blob, so no
        // per-operation annotations are required. We keep the (empty) crypt
        // annotations struct for forward compatibility with encryption context.
        let annotations = serde_json::to_value(AwsCryptAnnotations::default())
            .map_err(|e| Error::AwsKmsError(format!("serialize annotations failed: {e:?}")))?
            .as_object()
            .expect("must be an object")
            .to_owned();

        Ok((ciphertext, annotations))
    }
}

#[async_trait]
impl Decrypter for AwsKmsClient {
    async fn decrypt(
        &mut self,
        ciphertext: &[u8],
        key_id: &str,
        annotations: &Annotations,
    ) -> Result<Vec<u8>> {
        let crypt_annotations: AwsCryptAnnotations =
            serde_json::from_value(Value::Object(annotations.clone())).map_err(|e| {
                Error::AwsKmsError(format!("deserialize crypt annotations failed: {e:?}"))
            })?;

        let mut request = self
            .kms
            .decrypt()
            .key_id(key_id)
            .ciphertext_blob(Blob::new(ciphertext.to_vec()));

        if !crypt_annotations.encryption_context.is_empty() {
            request = request.set_encryption_context(Some(crypt_annotations.encryption_context));
        }

        let response = request
            .send()
            .await
            .map_err(|e| Error::AwsKmsError(format!("AWS KMS decrypt failed: {e:?}")))?;

        let plaintext = response
            .plaintext
            .ok_or_else(|| Error::AwsKmsError("AWS KMS decrypt returned no plaintext".into()))?
            .into_inner();

        Ok(plaintext)
    }
}

#[async_trait]
impl Getter for AwsKmsClient {
    async fn get_secret(&self, name: &str, annotations: &Annotations) -> Result<Vec<u8>> {
        let secret_annotations: AwsSecretAnnotations =
            serde_json::from_value(Value::Object(annotations.clone())).map_err(|e| {
                Error::AwsKmsError(format!("deserialize secret annotations failed: {e:?}"))
            })?;

        let mut request = self.secrets_manager.get_secret_value().secret_id(name);

        if !secret_annotations.version_id.is_empty() {
            request = request.version_id(secret_annotations.version_id);
        }
        if !secret_annotations.version_stage.is_empty() {
            request = request.version_stage(secret_annotations.version_stage);
        }

        let response = request.send().await.map_err(|e| {
            Error::AwsKmsError(format!(
                "AWS Secrets Manager get_secret_value failed: {e:?}"
            ))
        })?;

        if let Some(secret_string) = response.secret_string {
            return Ok(secret_string.into_bytes());
        }
        if let Some(secret_binary) = response.secret_binary {
            return Ok(secret_binary.into_inner());
        }

        Err(Error::AwsKmsError(
            "AWS Secrets Manager secret has neither a string nor a binary value".into(),
        ))
    }
}

#[async_trait]
impl Setter for AwsKmsClient {
    async fn set_secret(&mut self, content: Vec<u8>, name: String) -> Result<Annotations> {
        // Try to create the secret. If it already exists, add a new version
        // instead. Any other error is surfaced to the caller.
        if let Err(sdk_error) = self
            .secrets_manager
            .create_secret()
            .name(&name)
            .secret_binary(Blob::new(content.clone()))
            .send()
            .await
        {
            let service_error = sdk_error.into_service_error();
            if service_error.is_resource_exists_exception() {
                self.secrets_manager
                    .put_secret_value()
                    .secret_id(&name)
                    .secret_binary(Blob::new(content))
                    .send()
                    .await
                    .map_err(|e| {
                        Error::AwsKmsError(format!(
                            "AWS Secrets Manager put_secret_value failed: {e:?}"
                        ))
                    })?;
            } else {
                return Err(Error::AwsKmsError(format!(
                    "AWS Secrets Manager create_secret failed: {service_error:?}"
                )));
            }
        }

        let annotations = serde_json::to_value(AwsSecretAnnotations::default())
            .map_err(|e| Error::AwsKmsError(format!("serialize annotations failed: {e:?}")))?
            .as_object()
            .expect("must be an object")
            .to_owned();

        Ok(annotations)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::annotations::AwsProviderSettings;
    use super::AwsKmsClient;

    fn test_client(region: &str) -> AwsKmsClient {
        // `new` only builds SDK config; it performs no network I/O, so this is a
        // pure unit test of the user-side construction path.
        AwsKmsClient::new(region, "AKIAEXAMPLE", "secret", None).expect("build client")
    }

    #[test]
    fn export_provider_settings_carries_region() {
        let client = test_client("eu-west-1");
        let provider_settings = client.export_provider_settings().unwrap();

        let parsed: AwsProviderSettings = serde_json::from_value(json!(provider_settings)).unwrap();
        assert_eq!(parsed.region, "eu-west-1");
    }

    #[test]
    fn export_provider_settings_round_trips_region() {
        // The exported settings are exactly what the decryptor side would
        // consume to rebuild a client, so the region must survive the trip.
        let region = "ap-south-1";
        let exported = test_client(region).export_provider_settings().unwrap();
        let value = serde_json::Value::Object(exported);
        assert_eq!(value, json!({ "region": region }));
    }

    #[test]
    fn client_accepts_session_token() {
        // Temporary STS credentials (with a session token) must construct too.
        AwsKmsClient::new("us-east-1", "ASIAEXAMPLE", "secret", Some("token"))
            .expect("build client with session token");
    }
}
