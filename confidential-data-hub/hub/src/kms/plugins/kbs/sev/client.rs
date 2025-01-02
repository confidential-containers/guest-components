// Copyright (c) 2022 IBM Corp.
// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;
use std::sync::LazyLock;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use crypto::WrapType;
use resource_uri::ResourceUri;
use serde::Deserialize;
use tokio::{fs, sync::RwLock};
use tonic::transport::Uri;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::kms::{plugins::kbs::Kbc, Error, Result};

use super::keybroker::{
    key_broker_service_client::KeyBrokerServiceClient, OnlineSecretRequest, RequestDetails,
};

const KEYS_PATH: &str = "/sys/kernel/security/secrets/coco/1ee27366-0c87-43a6-af48-28543eaf7cb0";

static ONLINE_SEV_KBC: LazyLock<RwLock<Option<RealKbc>>> = LazyLock::new(|| RwLock::new(None));

#[derive(Deserialize, Clone)]
struct Connection {
    client_id: Uuid,
    key: String,
}

struct RealKbc {
    client_id: Uuid,
    key: Vec<u8>,
    kbs_uri: Uri,
}

impl RealKbc {
    async fn new(kbs_uri: &str) -> Result<Self> {
        sev::mount_security_fs().map_err(|e| {
            Error::KbsClientError(format!("online-sev-kbc: mount security fs failed: {e:?}"))
        })?;
        let _secret_module = sev::SecretKernelModule::new().map_err(|e| {
            Error::KbsClientError(format!(
                "online-sev-kbc: create SecretKernelModule failed: {e:?}"
            ))
        })?;

        let connection_json = fs::read_to_string(KEYS_PATH).await.map_err(|e| {
            Error::KbsClientError(format!("online-sev-kbc: Read keys failed: {e:?}"))
        })?;
        fs::remove_file(KEYS_PATH)
            .await
            .expect("Failed to remove secret file");

        let connection: Connection = serde_json::from_str(&connection_json).map_err(|e| {
            Error::KbsClientError(format!("online-sev-kbc: deserialze keys failed: {e:?}"))
        })?;

        let key = STANDARD.decode(connection.key).map_err(|e| {
            Error::KbsClientError(format!(
                "online-sev-kbc: base64 decode connection key failed: {e:?}"
            ))
        })?;

        let kbs_uri = format!("http://{kbs_uri}").parse::<Uri>().map_err(|e| {
            Error::KbsClientError(format!("online-sev-kbc: parse kbs uri failed: {e:?}"))
        })?;
        let kbc = RealKbc {
            client_id: connection.client_id,
            key,
            kbs_uri,
        };

        Ok(kbc)
    }
}

pub struct OnlineSevKbc {}

impl OnlineSevKbc {
    pub async fn new(kbs_uri: &str) -> Result<Self> {
        if !ONLINE_SEV_KBC.read().await.is_none() {
            let mut writer = ONLINE_SEV_KBC.write().await;
            let kbc = RealKbc::new(kbs_uri).await?;
            *writer = Some(kbc);
        }

        Ok(Self {})
    }

    async fn get_resource_from_kbs(
        &self,
        resource_uri: ResourceUri,
        secret_type: &str,
    ) -> Result<Vec<u8>> {
        let reader = ONLINE_SEV_KBC.read().await;
        let kbc = reader.as_ref().expect("Must be initialized");
        let channel = tonic::transport::Channel::builder(kbc.kbs_uri.clone()).connect_lazy();
        let mut client = KeyBrokerServiceClient::new(channel);

        let guid = Uuid::new_v4().as_hyphenated().to_string();
        let secret_request = RequestDetails {
            guid: guid.clone(),
            format: "binary".to_string(),
            secret_type: secret_type.to_owned(),
            id: resource_uri.resource_path(),
        };

        let request = tonic::Request::new(OnlineSecretRequest {
            client_id: kbc.client_id.as_hyphenated().to_string(),
            secret_requests: vec![secret_request],
        });

        let response = client
            .get_online_secret(request)
            .await
            .map_err(|e| {
                Error::KbsClientError(format!(
                    "online-sev-kbc: sev get online secret failed: {e:?}"
                ))
            })?
            .into_inner();
        let decrypted_payload = crypto::decrypt(
            Zeroizing::new(kbc.key.clone()),
            STANDARD.decode(response.payload).map_err(|e| {
                Error::KbsClientError(format!(
                    "online-sev-kbc: base64 decode response.payload failed: {e:?}"
                ))
            })?,
            STANDARD.decode(response.iv).map_err(|e| {
                Error::KbsClientError(format!(
                    "online-sev-kbc: base64 decode response.iv failed: {e:?}"
                ))
            })?,
            WrapType::Aes256Gcm,
        )
        .map_err(|e| {
            Error::KbsClientError(format!("online-sev-kbc: decrypt payload failed: {e:?}"))
        })?;

        let payload_dict: HashMap<String, Vec<u8>> = bincode::deserialize(&decrypted_payload)
            .map_err(|e| {
                Error::KbsClientError(format!(
                    "online-sev-kbc: deserailize payload dictionary failed: {e:?}"
                ))
            })?;
        let res = payload_dict
            .get(&guid)
            .ok_or(Error::KbsClientError(format!(
                "online-sev-kbc: No guid {guid} found in the returned payload dictionary."
            )))?
            .to_vec();

        Ok(res)
    }
}

#[async_trait]
impl Kbc for OnlineSevKbc {
    async fn get_resource(&mut self, rid: ResourceUri) -> Result<Vec<u8>> {
        let reader = ONLINE_SEV_KBC.read().await;
        let kbc = reader.as_ref().expect("Must be initialized");
        match &rid.r#type[..] {
            "client-id" => Ok(kbc.client_id.hyphenated().to_string().into_bytes()),
            _ => self.get_resource_from_kbs(rid, "resource").await,
        }
    }
}
