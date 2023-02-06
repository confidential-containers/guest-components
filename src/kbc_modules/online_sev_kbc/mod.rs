// Copyright (c) 2022 IBM Corp.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::common::crypto::WrapType;
use crate::common::{crypto, sev::*};
use crate::kbc_modules::{KbcCheckInfo, KbcInterface};
use crate::uri::ResourceUri;

use anyhow::*;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use tonic::codegen::http::Uri;
use uuid::Uuid;
use zeroize::Zeroizing;

use keybroker::key_broker_service_client::KeyBrokerServiceClient;
use keybroker::{OnlineSecretRequest, RequestDetails};

use super::AnnotationPacket;

#[rustfmt::skip]
mod keybroker;

const KEYS_PATH: &str = "/sys/kernel/security/secrets/coco/1ee27366-0c87-43a6-af48-28543eaf7cb0";

#[derive(Deserialize, Clone)]
struct Connection {
    client_id: Uuid,
    key: String,
}

pub struct OnlineSevKbc {
    // KBS info for compatibility; unused
    kbs_info: HashMap<String, String>,
    kbs_uri: String,
    connection: Result<Connection>,
}

#[async_trait]
impl KbcInterface for OnlineSevKbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Ok(KbcCheckInfo {
            kbs_info: self.kbs_info.clone(),
        })
    }

    async fn decrypt_payload(&mut self, annotation_packet: AnnotationPacket) -> Result<Vec<u8>> {
        let key = self.get_key_from_kbs(annotation_packet.kid).await?;
        let plain_payload = crypto::decrypt(
            key,
            base64::decode(annotation_packet.wrapped_data)?,
            base64::decode(annotation_packet.iv)?,
            &annotation_packet.wrap_type,
        )?;

        Ok(plain_payload)
    }

    async fn get_resource(&mut self, rid: ResourceUri) -> Result<Vec<u8>> {
        match &rid.r#type[..] {
            "client-id" => {
                let connection = self
                    .connection
                    .as_ref()
                    .map_err(|e| anyhow!("Failed to get injected connection. {}", e))?;
                Ok(connection.client_id.hyphenated().to_string().into_bytes())
            }
            _ => self.get_resource_from_kbs(rid).await,
        }
    }
}

impl OnlineSevKbc {
    #[allow(clippy::new_without_default)]
    pub fn new(kbs_uri: String) -> OnlineSevKbc {
        OnlineSevKbc {
            kbs_info: HashMap::new(),
            kbs_uri,
            connection: load_connection(),
        }
    }

    async fn query_kbs(&self, secret_type: String, secret_id: String) -> Result<Vec<u8>> {
        let uri = format!("http://{}", self.kbs_uri).parse::<Uri>()?;

        let channel = tonic::transport::Channel::builder(uri).connect_lazy();
        let mut client = KeyBrokerServiceClient::new(channel);

        let connection = self
            .connection
            .as_ref()
            .map_err(|e| anyhow!("Failed to get injected connection. {}", e))?;
        let guid = Uuid::new_v4().as_hyphenated().to_string();
        let secret_request = RequestDetails {
            guid: guid.clone(),
            format: "binary".to_string(),
            secret_type,
            id: secret_id,
        };

        let request = tonic::Request::new(OnlineSecretRequest {
            client_id: connection.client_id.as_hyphenated().to_string(),
            secret_requests: vec![secret_request],
        });

        let response = client.get_online_secret(request).await?.into_inner();
        let decrypted_payload = crypto::decrypt(
            Zeroizing::new(base64::decode(connection.key.clone())?),
            base64::decode(response.payload)?,
            base64::decode(response.iv)?,
            WrapType::Aes256Gcm.as_ref(),
        )?;

        let payload_dict: HashMap<String, Vec<u8>> = bincode::deserialize(&decrypted_payload)?;

        Ok(payload_dict
            .get(&guid)
            .ok_or_else(|| anyhow!("Secret UUID not found."))?
            .to_vec())
    }

    async fn get_key_from_kbs(&self, rid: ResourceUri) -> Result<Zeroizing<Vec<u8>>> {
        let key = self
            .query_kbs("key".to_string(), rid.resource_path())
            .await?;
        let key = Zeroizing::new(key);
        Ok(key)
    }

    async fn get_resource_from_kbs(&self, rid: ResourceUri) -> Result<Vec<u8>> {
        self.query_kbs("resource".to_string(), rid.resource_path())
            .await
    }
}

fn load_connection() -> Result<Connection> {
    mount_security_fs()?;
    let _secret_module = SecretKernelModule::new()?;

    let connection_json = fs::read_to_string(KEYS_PATH)?;
    fs::remove_file(KEYS_PATH).expect("Failed to remove secret file.");

    Ok(serde_json::from_str(&connection_json)?)
}
