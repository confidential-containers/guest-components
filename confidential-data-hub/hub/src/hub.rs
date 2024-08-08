// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use async_trait::async_trait;
use kms::{Annotations, ProviderSettings};
use log::info;
use storage::volume_type::Storage;

use crate::{DataHub, Error, Result};

pub struct Hub {
    pub(crate) credentials: HashMap<String, String>,
}

impl Hub {
    pub async fn new(credentials: HashMap<String, String>) -> Result<Self> {
        let mut hub = Self { credentials };

        hub.init().await?;
        Ok(hub)
    }
}

#[async_trait]
impl DataHub for Hub {
    async fn unseal_secret(&self, secret: Vec<u8>) -> Result<Vec<u8>> {
        info!("unseal secret called");

        let res = secret::unseal_secret(&secret).await?;

        Ok(res)
    }

    async fn unwrap_key(&self, annotation_packet: &[u8]) -> Result<Vec<u8>> {
        info!("unwrap key called");

        let lek = image::unwrap_key(annotation_packet).await?;
        Ok(lek)
    }

    async fn get_resource(&self, uri: String) -> Result<Vec<u8>> {
        info!("get resource called: {uri}");
        // to initialize a get_resource_provider client we do not need the ProviderSettings.
        let client = kms::new_getter("kbs", ProviderSettings::default())
            .await
            .map_err(|e| Error::KbsClient { source: e })?;

        // to get resource using a get_resource_provider client we do not need the Annotations.
        let res = client
            .get_secret(&uri, &Annotations::default())
            .await
            .map_err(|e| Error::GetResource { source: e })?;
        Ok(res)
    }

    async fn secure_mount(&self, storage: Storage) -> Result<String> {
        info!("secure mount called");
        let res = storage.mount().await?;
        Ok(res)
    }
}
