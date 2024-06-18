// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::env;

use anyhow::bail;
use log::info;
use serde::Deserialize;
use serde_json::Value;
use tokio::fs;

use crate::{Annotations, ProviderSettings};
use crate::{Error, Result};

use super::sts_token_client::credential::StsCredential;
use super::{sts_token_client::StsTokenClient, ALIYUN_IN_GUEST_DEFAULT_KEY_PATH};

#[derive(Clone, Debug)]
pub struct EcsRamRoleClient {
    ecs_ram_role_name: String,
    region_id: String,
    endpoint: String,
}

#[derive(Deserialize)]
pub struct EcsRamRoleJson {
    ecs_ram_role_name: String,
    region_id: String,
}

impl EcsRamRoleClient {
    pub fn new(ecs_ram_role_name: String, region_id: String) -> Self {
        let endpoint = format!("kms.{region_id}.aliyuncs.com");

        Self {
            ecs_ram_role_name,
            region_id,
            endpoint,
        }
    }

    /// This new function is used by a in-pod client. The side-effect is to read the
    /// [`ALIYUN_IN_GUEST_DEFAULT_KEY_PATH`] which is the by default path where the credential
    /// to access kms is saved.
    pub async fn from_provider_settings(_provider_settings: &ProviderSettings) -> Result<Self> {
        let key_path = env::var("ALIYUN_IN_GUEST_KEY_PATH")
            .unwrap_or(ALIYUN_IN_GUEST_DEFAULT_KEY_PATH.to_owned());
        info!("ALIYUN_IN_GUEST_KEY_PATH = {}", key_path);

        let ecs_ram_role_path = format!("{}/ecsRamRole.json", key_path);

        let ecs_ram_role_str = fs::read_to_string(ecs_ram_role_path).await.map_err(|e| {
            Error::AliyunKmsError(format!(
                "read ecs_ram_role with `fs::read_to_string()` failed: {e}"
            ))
        })?;

        let ecs_ram_role_json: EcsRamRoleJson =
            serde_json::from_str(&ecs_ram_role_str).map_err(|e| {
                Error::AliyunKmsError(format!("parse ecs_ram_role JSON file failed: {e}"))
            })?;

        Ok(Self::new(
            ecs_ram_role_json.ecs_ram_role_name,
            ecs_ram_role_json.region_id,
        ))
    }

    /// Export the [`ProviderSettings`] of the current client. This function is to be used
    /// in the encryptor side. The [`ProviderSettings`] will be used to initial a client
    /// in the decryptor side.
    pub fn export_provider_settings(&self) -> ProviderSettings {
        serde_json::Map::<String, Value>::new()
    }
}

impl EcsRamRoleClient {
    async fn get_session_credential(&self) -> anyhow::Result<StsCredential> {
        let request_url = format!(
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/{}",
            self.ecs_ram_role_name
        );

        let response = reqwest::get(&request_url).await?;
        let body = if response.status().is_success() {
            response.text().await?
        } else {
            bail!(
                "Request session_credential failed with status: {}",
                response.status(),
            );
        };

        let credential = serde_json::from_str(&body)?;

        Ok(credential)
    }

    pub async fn get_secret(&mut self, name: &str, annotations: &Annotations) -> Result<Vec<u8>> {
        let sts_credential = self
            .get_session_credential()
            .await
            .map_err(|e| Error::AliyunKmsError(format!("Get sts token from IMDS failed: {e}")))?;

        let mut client = StsTokenClient::from_sts_token(
            sts_credential,
            self.endpoint.clone(),
            self.region_id.clone(),
        )
        .map_err(|e| {
            Error::AliyunKmsError(format!("Failed to create HTTP client to get secret: {e}"))
        })?;

        client.get_secret(name, annotations).await
    }
}
