// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{collections::HashMap, path::Path};

use async_trait::async_trait;
use image_rs::{builder::ClientBuilder, config::ImageConfig, image::ImageClient};
use kms::{Annotations, ProviderSettings};
use log::{debug, info, warn};
use std::env;
use storage::volume_type::Storage;
use tokio::sync::{Mutex, OnceCell};

use crate::{CdhConfig, DataHub, Error, Result};

pub struct Hub {
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
            .await
            .map_err(|e| Error::ImagePull { source: e })?;
        Ok(manifest_digest)
    }
}

async fn initialize_image_client(config: ImageConfig) -> Result<Mutex<ImageClient>> {
    debug!("Image client lazy initializing...");
    // TODO: move the proxy envs to image-rs' PullClient once it supports
    // Current the whole process of CDH would be influenced by the HTTPS_PROXY env
    if let Some(https_proxy) = &config.image_pull_proxy {
        match env::var("HTTPS_PROXY") {
                Ok(e) => warn!("`image_pull_proxy` is given from config but the current process has a `HTTPS_PROXY` env value {e}, skip override."),
                Err(env::VarError::NotPresent) => {
                    info!("image_pull_proxy is set to: {}", https_proxy);
                    env::set_var("HTTPS_PROXY", https_proxy);
                }
                Err(env::VarError::NotUnicode(_)) => warn!("`image_pull_proxy` is given from config but the current process has a non-unicode `HTTPS_PROXY`, skip override."),
            }
    }

    if let Some(no_proxy) = &config.skip_proxy_ips {
        match env::var("NO_PROXY") {
                Ok(e) => warn!("`skip_proxy_ips` is given from config but the current process has one `NO_PROXY` env value {e}, skip override."),
                Err(env::VarError::NotPresent) => {
                    info!("no_proxy is set to: {}", no_proxy);
                    env::set_var("NO_PROXY", no_proxy);
                }
                Err(env::VarError::NotUnicode(_)) => warn!("`skip_proxy_ips` is given from config but the current process has a non-unicode env `NO_PROXY`, skip override."),
            }
    }

    let image_client = Into::<ClientBuilder>::into(config)
        .build()
        .await
        .map_err(|e| {
            Error::InitializationFailed(format!("failed to initialize image pull client :{e:?}"))
        })?;

    Ok(Mutex::new(image_client))
}
