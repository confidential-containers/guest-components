// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{collections::HashMap, path::Path};

use async_trait::async_trait;
use image_rs::{builder::ClientBuilder, config::ImageConfig, image::ImageClient};
use kms::{Annotations, ProviderSettings};
use log::{debug, info};
use tokio::sync::{Mutex, OnceCell};

use crate::storage::volume_type::Storage;
use crate::{image, secret, CdhConfig, DataHub, Error, Result};

pub struct Hub {
    #[allow(dead_code)]
    pub(crate) credentials: HashMap<String, String>,
    image_client: OnceCell<Mutex<ImageClient>>,
    config: CdhConfig,
}

impl Hub {
    pub async fn new(config: CdhConfig) -> Result<Self> {
        config.set_configuration_envs();
        let credentials = config
            .credentials
            .iter()
            .map(|it| (it.path.clone(), it.resource_uri.clone()))
            .collect();

        let mut hub = Self {
            credentials,
            config,
            image_client: OnceCell::const_new(),
        };

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

    async fn pull_image(&self, image_url: &str, bundle_path: &str) -> Result<String> {
        let client = self
            .image_client
            .get_or_try_init(
                || async move { initialize_image_client(self.config.image.clone()).await },
            )
            .await?;
        let manifest_digest = client
            .lock()
            .await
            .pull_image(image_url, Path::new(bundle_path), &None, &None)
            .await?;
        Ok(manifest_digest)
    }
}

async fn initialize_image_client(config: ImageConfig) -> Result<Mutex<ImageClient>> {
    debug!("Image client lazy initializing...");

    let image_client = Into::<ClientBuilder>::into(config).build().await?;

    Ok(Mutex::new(image_client))
}
