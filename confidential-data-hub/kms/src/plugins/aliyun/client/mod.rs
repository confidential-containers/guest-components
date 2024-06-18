// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
use const_format::concatcp;
use serde_json::json;
use sts_token_client::StsTokenClient;

mod client_key_client;
mod ecs_ram_role_client;
mod sts_token_client;

use crate::plugins::_IN_GUEST_DEFAULT_KEY_PATH;
use crate::{Annotations, Decrypter, Encrypter, Getter, ProviderSettings};
use crate::{Error, Result};

use client_key_client::ClientKeyClient;
use ecs_ram_role_client::EcsRamRoleClient;

#[derive(Clone, Debug)]
enum Client {
    ClientKey {
        client_key_client: ClientKeyClient,
    },
    EcsRamRole {
        ecs_ram_role_client: EcsRamRoleClient,
    },
    StsToken {
        client: StsTokenClient,
    },
}

pub struct AliyunKmsClient {
    inner_client: Client,
}

const ALIYUN_IN_GUEST_DEFAULT_KEY_PATH: &str = concatcp!(_IN_GUEST_DEFAULT_KEY_PATH, "/aliyun");

impl AliyunKmsClient {
    pub fn new(
        client_key: &str,
        kms_instance_id: &str,
        password: &str,
        cert_pem: &str,
    ) -> Result<Self> {
        Self::new_client_key_client(client_key, kms_instance_id, password, cert_pem)
    }

    pub fn new_client_key_client(
        client_key: &str,
        kms_instance_id: &str,
        password: &str,
        cert_pem: &str,
    ) -> Result<Self> {
        let inner_client = Client::ClientKey {
            client_key_client: ClientKeyClient::new(
                client_key,
                kms_instance_id,
                password,
                cert_pem,
            )?,
        };

        Ok(Self { inner_client })
    }

    pub fn new_ecs_ram_role_client(ecs_ram_role_name: &str, region_id: &str) -> Self {
        let inner_client = Client::EcsRamRole {
            ecs_ram_role_client: EcsRamRoleClient::new(
                ecs_ram_role_name.to_string(),
                region_id.to_string(),
            ),
        };

        Self { inner_client }
    }

    /// This new function is used by a in-pod client. The side-effect is to read the
    /// [`ALIYUN_IN_GUEST_DEFAULT_KEY_PATH`] which is the by default path where the credential
    /// to access kms is saved.
    pub async fn from_provider_settings(provider_settings: &ProviderSettings) -> Result<Self> {
        let client_type = if let Some(client_type_value) = provider_settings.get("client_type") {
            match client_type_value.as_str() {
                Some(client_type) => client_type,
                None => {
                    return Err(Error::AliyunKmsError(
                        "client type value is not str.".to_string(),
                    ))
                }
            }
        } else {
            return Err(Error::AliyunKmsError("client type not exist.".to_string()));
        };

        let inner_client = match client_type {
            "client_key" => Client::ClientKey {
                client_key_client: ClientKeyClient::from_provider_settings(provider_settings)
                    .await
                    .map_err(|e| {
                        Error::AliyunKmsError(format!(
                            "build ClientKeyClient with `from_provider_settings()` failed: {e}"
                        ))
                    })?,
            },
            "ecs_ram_role" => Client::EcsRamRole {
                ecs_ram_role_client: EcsRamRoleClient::from_provider_settings(provider_settings)
                    .await
                    .map_err(|e| {
                        Error::AliyunKmsError(format!(
                            "build EcsRamRoleClient with `from_provider_settings()` failed: {e}"
                        ))
                    })?,
            },
            "sts_token" => Client::StsToken {
                client: StsTokenClient::from_provider_settings(provider_settings)
                    .await
                    .map_err(|e| {
                        Error::AliyunKmsError(format!(
                            "build EcsRamRoleClient with `from_provider_settings()` failed: {e}"
                        ))
                    })?,
            },
            _ => return Err(Error::AliyunKmsError("client type invalid.".to_string())),
        };

        Ok(Self { inner_client })
    }

    /// Export the [`ProviderSettings`] of the current client. This function is to be used
    /// in the encryptor side. The [`ProviderSettings`] will be used to initial a client
    /// in the decryptor side.
    pub fn export_provider_settings(&self) -> Result<ProviderSettings> {
        match &self.inner_client {
            Client::ClientKey { client_key_client } => {
                let mut provider_settings =
                    client_key_client.export_provider_settings().map_err(|e| {
                        Error::AliyunKmsError(format!(
                            "ClientKeyClient `export_provider_settings()` failed: {e}"
                        ))
                    })?;

                provider_settings.insert(String::from("client_type"), json!("client_key"));

                Ok(provider_settings)
            }
            Client::EcsRamRole {
                ecs_ram_role_client,
            } => {
                let mut provider_settings = ecs_ram_role_client.export_provider_settings();

                provider_settings.insert(String::from("client_type"), json!("ecs_ram_role"));

                Ok(provider_settings)
            }
            Client::StsToken { client } => {
                let mut provider_settings = client.export_provider_settings();

                provider_settings.insert(String::from("client_type"), json!("sts_token"));

                Ok(provider_settings)
            }
        }
    }
}

#[async_trait]
impl Encrypter for AliyunKmsClient {
    async fn encrypt(&mut self, data: &[u8], key_id: &str) -> Result<(Vec<u8>, Annotations)> {
        match &mut self.inner_client {
            Client::ClientKey {
                ref mut client_key_client,
            } => client_key_client.encrypt(data, key_id).await,
            Client::EcsRamRole { .. } => Err(Error::AliyunKmsError(
                "Encrypter does not suppot accessing through Aliyun EcsRamRole".to_string(),
            )),
            Client::StsToken { .. } => Err(Error::AliyunKmsError(
                "Encrypter does not suppot accessing through Aliyun StsToken".to_string(),
            )),
        }
    }
}

#[async_trait]
impl Decrypter for AliyunKmsClient {
    async fn decrypt(
        &mut self,
        ciphertext: &[u8],
        key_id: &str,
        annotations: &Annotations,
    ) -> Result<Vec<u8>> {
        match &mut self.inner_client {
            Client::ClientKey {
                ref mut client_key_client,
            } => {
                client_key_client
                    .decrypt(ciphertext, key_id, annotations)
                    .await
            }
            Client::EcsRamRole { .. } => Err(Error::AliyunKmsError(
                "Encrypter does not suppot accessing through Aliyun EcsRamRole".to_string(),
            )),
            Client::StsToken { .. } => Err(Error::AliyunKmsError(
                "Encrypter does not suppot accessing through Aliyun StsToken".to_string(),
            )),
        }
    }
}

#[async_trait]
impl Getter for AliyunKmsClient {
    async fn get_secret(&mut self, name: &str, annotations: &Annotations) -> Result<Vec<u8>> {
        match &mut self.inner_client {
            Client::ClientKey {
                ref mut client_key_client,
            } => client_key_client.get_secret(name, annotations).await,
            Client::EcsRamRole {
                ref mut ecs_ram_role_client,
            } => ecs_ram_role_client.get_secret(name, annotations).await,
            Client::StsToken { ref mut client } => client.get_secret(name, annotations).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::{json, Map, Value};

    use crate::{
        plugins::aliyun::client::AliyunKmsClient, Annotations, Decrypter, Encrypter, Getter,
    };

    #[rstest]
    #[ignore]
    #[case(b"this is a test plaintext")]
    #[ignore]
    #[case(b"this is a another test plaintext")]
    #[tokio::test]
    async fn key_lifetime(#[case] plaintext: &[u8]) {
        let kid = "alias/test_key_id";
        let provider_settings = json!({
            "client_type": "client_key",
            "client_key_id": "KAAP.f4c8****",
            "kms_instance_id": "kst-shh6****",
        });
        // init encrypter at user side
        let provider_settings = provider_settings.as_object().unwrap().to_owned();
        let mut encryptor = AliyunKmsClient::from_provider_settings(&provider_settings)
            .await
            .unwrap();

        // do encryption
        let (ciphertext, secret_settings) =
            encryptor.encrypt(plaintext, kid).await.expect("encrypt");
        let provider_settings = encryptor.export_provider_settings().unwrap();

        // init decrypter in a guest
        let mut decryptor = AliyunKmsClient::from_provider_settings(&provider_settings)
            .await
            .unwrap();

        // do decryption
        let decrypted = decryptor
            .decrypt(&ciphertext, kid, &secret_settings)
            .await
            .expect("decrypt");

        assert_eq!(decrypted, plaintext);
    }

    #[rstest]
    #[ignore]
    #[case("client_key")]
    #[ignore]
    #[case("ecs_ram_role")]
    #[tokio::test]
    async fn get_secret(#[case] client_type: &str) {
        let secret_name = "test_secret";
        let provider_settings = json!({
            "client_type": client_type,
            "client_key_id": "KAAP.f4c8****",
            "kms_instance_id": "kst-shh6****",
        });
        // init getter at user side
        let provider_settings = provider_settings.as_object().unwrap().to_owned();
        let mut getter = AliyunKmsClient::from_provider_settings(&provider_settings)
            .await
            .unwrap();

        // do get
        let mut annotations: Annotations = Map::<String, Value>::new();
        annotations.insert("version_stage".to_string(), Value::String("".to_string()));
        annotations.insert("version_id".to_string(), Value::String("".to_string()));
        let secret_value = getter
            .get_secret(secret_name, &annotations)
            .await
            .expect("get_secret_with_client_key");

        // We have set "test_secret_value" as secret on Aliyun KMS console.
        assert_eq!(String::from_utf8_lossy(&secret_value), "test_secret_value");
    }
}
