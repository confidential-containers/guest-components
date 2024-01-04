// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use image::AnnotationPacket;
use kms::{Annotations, ProviderSettings};
use log::info;
use secret::secret::Secret;
use storage::volume_type::Storage;

use crate::{DataHub, Error, Result};

pub struct Hub {}

impl Hub {
    pub async fn new() -> Result<Self> {
        let mut hub = Self {};

        hub.init().await?;
        Ok(hub)
    }
}

#[async_trait]
impl DataHub for Hub {
    async fn unseal_secret(&self, secret: Vec<u8>) -> Result<Vec<u8>> {
        info!("unseal secret called");
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

    async fn unwrap_key(&self, annotation_packet: &[u8]) -> Result<Vec<u8>> {
        info!("unwrap key called");
        let annotation_packet: AnnotationPacket = serde_json::from_slice(annotation_packet)
            .map_err(|e| Error::ImageDecryption(format!("illegal AnnotationPacket format: {e}")))?;
        let lek = annotation_packet
            .unwrap_key()
            .await
            .map_err(|e| Error::ImageDecryption(format!("unwrap key failed: {e}")))?;
        Ok(lek)
    }

    async fn get_resource(&self, uri: String) -> Result<Vec<u8>> {
        info!("get resource called: {uri}");
        // to initialize a get_resource_provider client we do not need the ProviderSettings.
        let mut client = kms::new_getter("kbs", ProviderSettings::default())
            .await
            .map_err(|e| Error::GetResource(format!("create kbs client failed: {e}")))?;

        // to get resource using a get_resource_provider client we do not need the Annotations.
        let res = client
            .get_secret(&uri, &Annotations::default())
            .await
            .map_err(|e| Error::GetResource(format!("get rersource failed: {e}")))?;
        Ok(res)
    }

    async fn secure_mount(&self, storage: Storage) -> Result<String> {
        info!("secure mount called");
        let res = storage
            .mount()
            .await
            .map_err(|e| Error::SecureMount(e.to_string()))?;
        Ok(res)
    }
}
