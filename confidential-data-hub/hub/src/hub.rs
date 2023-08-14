// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use kms::{Annotations, ProviderSettings};
use secret::secret::Secret;
use tokio::fs;

use crate::{DataHub, Error, Result};

pub struct Hub {
    /// the get resource provider type. Semantically same as kbc.
    get_resource_provider: String,
}

impl Hub {
    pub async fn new() -> Result<Self> {
        let get_resource_provider = Self::get_resource_provider().await?;
        let mut hub = Self {
            get_resource_provider,
        };

        hub.init().await?;
        Ok(hub)
    }

    async fn get_resource_provider() -> Result<String> {
        let cmdline = fs::read_to_string("/proc/cmdline")
            .await
            .map_err(|e| Error::InitializationFailed(format!("read kernel cmdline failed: {e}")))?;
        let resource_provider = cmdline
            .split_ascii_whitespace()
            .find(|para| para.starts_with("agent.aa_kbc_params="))
            .ok_or(Error::InitializationFailed(
                "no `agent.aa_kbc_params` provided in kernel commandline!".into(),
            ))?
            .split("::")
            .next()
            .ok_or(Error::InitializationFailed(
                "illegal input `agent.aa_kbc_params` format".into(),
            ))?
            .to_string();
        Ok(resource_provider)
    }
}

#[async_trait]
impl DataHub for Hub {
    async fn unseal_secret(&self, secret: Vec<u8>) -> Result<Vec<u8>> {
        // TODO: verify the jws signature using the key specified by `kid`
        // in header. Here we directly get the JWS payload
        let payload = secret
            .split(|c| *c == b'.')
            .nth(1)
            .ok_or_else(|| Error::UnsealSecret("illegal input sealed secret (not a JWS)".into()))?;

        let secret_json = STANDARD.decode(payload).map_err(|e| {
            Error::UnsealSecret(format!(
                "illegal input sealed secret (JWS body is not standard base64 encoded): {e}"
            ))
        })?;
        let secret: Secret = serde_json::from_slice(&secret_json).map_err(|e| {
            Error::UnsealSecret(format!(
                "illegal input sealed secret format (json deseralization failed): {e}"
            ))
        })?;

        let res = secret
            .unseal()
            .await
            .map_err(|e| Error::UnsealSecret(format!("unseal failed: {e}")))?;
        Ok(res)
    }

    async fn unwrap_key(&self, _annotation: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }

    async fn get_resource(&self, uri: String) -> Result<Vec<u8>> {
        // to initialize a get_resource_provider client we do not need the ProviderSettings.
        let mut client = kms::new_getter(&self.get_resource_provider, ProviderSettings::default())
            .await
            .map_err(|e| Error::GetResource(format!("create kbs client failed: {e}")))?;

        let annotations = match &self.get_resource_provider[..] {
            "online_sev_kbc" | "sev" => {
                serde_json::from_str::<Annotations>(r#"{"secret_type":"resource"}"#)
                    .expect("deserialize sev hardcode failed")
            }
            _ => Annotations::default(),
        };

        // to get resource using a get_resource_provider client we do not need the Annotations.
        let res = client
            .get_secret(&uri, &annotations)
            .await
            .map_err(|e| Error::GetResource(format!("get rersource failed: {e}")))?;
        Ok(res)
    }
}
