// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use async_trait::async_trait;
use image_rs::image::ImageClient;
use kms::{Annotations, ProviderSettings};
use log::{info, warn};
use std::env;
use storage::volume_type::Storage;

use crate::{CdhConfig, DataHub, Error, Result};

pub struct Hub {
    pub(crate) credentials: HashMap<String, String>,
    image_client: tokio::sync::Mutex<image_rs::image::ImageClient>,
}

impl Hub {
    pub async fn new(config: CdhConfig) -> Result<Self> {
        config.set_configuration_envs();
        let credentials = config
            .credentials
            .iter()
            .map(|it| (it.path.clone(), it.resource_uri.clone()))
            .collect();

        let mut image_client = match config.image.work_dir {
            Some(work_dir) => ImageClient::new(work_dir.into()),
            None => ImageClient::default(),
        };

        if let Some(uri) = config.image.authenticated_registry_credentials_uri {
            if !uri.is_empty() {
                image_client.config.auth = true;
                image_client.config.file_paths.auth_file = uri;
            }
        }

        if let Some(uri) = config.image.image_security_policy_uri {
            if !uri.is_empty() {
                image_client.config.security_validate = true;
                image_client.config.file_paths.policy_path = uri;
            }
        }

        if let Some(uri) = config.image.sigstore_config_uri {
            if !uri.is_empty() {
                image_client.config.file_paths.sigstore_config = uri;
            }
        }

        if let Some(number) = config.image.max_concurrent_layer_downloads_per_image {
            image_client.config.max_concurrent_download = number;
        }

        // TODO: move the proxy envs to image-rs' PullClient once it supports
        // Current the whole process of CDH would be influenced by the HTTPS_PROXY env
        if let Some(https_proxy) = config.image.image_pull_proxy {
            match env::var("HTTPS_PROXY") {
                Ok(e) => warn!("`image_pull_proxy` is given from config but the current process has a `HTTPS_PROXY` env value {e:?}, skip override."),
                Err(env::VarError::NotPresent) => {
                    info!("image_pull_proxy is set to: {}", https_proxy);
                    env::set_var("HTTPS_PROXY", https_proxy);
                }
                Err(env::VarError::NotUnicode(_)) => warn!("`image_pull_proxy` is given from config but the current process has a non-unicode `HTTPS_PROXY`, skip override."),
            }
        }

        if let Some(no_proxy) = config.image.skip_proxy_ips {
            match env::var("NO_PROXY") {
                Ok(e) => warn!("`skip_proxy_ips` is given from config but the current process has one `NO_PROXY` env value {e:?}, skip override."),
                Err(env::VarError::NotPresent) => {
                    info!("no_proxy is set to: {}", no_proxy);
                    env::set_var("NO_PROXY", no_proxy);
                }
                Err(env::VarError::NotUnicode(_)) => warn!("`skip_proxy_ips` is given from config but the current process has a non-unicode env `NO_PROXY`, skip override."),
            }
        }

        let mut hub = Self {
            credentials,
            image_client: tokio::sync::Mutex::new(image_client),
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
        use std::path::Path;

        let manifest_digest = self
            .image_client
            .lock()
            .await
            .pull_image(image_url, Path::new(bundle_path), &None, &None)
            .await
            .map_err(|e| Error::ImagePull { source: e })?;
        Ok(manifest_digest)
    }
}
