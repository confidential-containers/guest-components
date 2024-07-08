// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use async_trait::async_trait;
use kms::{Annotations, ProviderSettings};
use log::info;
use storage::volume_type::Storage;

use crate::{CdhConfig, DataHub, Error, Result};

#[cfg(feature = "image-pull")]
const IMAGE_WORK_DIR: &str = "/tmp/image-rs";

pub struct Hub {
    pub(crate) credentials: HashMap<String, String>,

    #[cfg(feature = "image-pull")]
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

        cfg_if::cfg_if! {
            if #[cfg(feature = "image-pull")] {
                use std::env;
                use image_rs::image::ImageClient;

                let work_dir =
                    std::env::var("IMAGE_PULL_WORK_DIR").unwrap_or(IMAGE_WORK_DIR.to_owned());
                let mut image_client = ImageClient::new(work_dir.clone().into());
                image_client.config.auth = config.image.auth;
                image_client.config.file_paths.auth_file = config.image.auth_uri;
                image_client.config.file_paths.policy_path = config.image.policy_uri;
                image_client.config.file_paths.sigstore_config = config.image.sigstore_config_uri;
                image_client.config.max_concurrent_download = config.image.max_concurrent_download;
                image_client.config.security_validate = config.image.security_validate;

                if env::var("HTTPS_PROXY").is_err() {
                    let https_proxy = config.image.https_proxy;
                    if !https_proxy.is_empty() {
                        env::set_var("HTTPS_PROXY", https_proxy);
                    }
                }

                match env::var("HTTPS_PROXY") {
                    Ok(val) => info!("https_proxy is set to: {val}"),
                    Err(e) => log::warn!("failed to set https_proxy: {e}"),
                };

                if env::var("NO_PROXY").is_err() {
                    let no_proxy = config.image.no_proxy;
                    if !no_proxy.is_empty() {
                        env::set_var("NO_PROXY", no_proxy);
                    }
                }

                match env::var("NO_PROXY") {
                    Ok(val) => info!("no_proxy is set to: {val}"),
                    Err(e) => log::warn!("failed to set no_proxy: {e}"),
                };

                let mut hub = Self {
                    credentials,
                    image_client: tokio::sync::Mutex::new(image_client),
                };

                hub.init().await?;
                Ok(hub)
            } else {
                let mut hub = Self {
                    credentials,
                };

                hub.init().await?;
                Ok(hub)
            }
        }
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
        let mut client = kms::new_getter("kbs", ProviderSettings::default())
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

    #[cfg(feature = "image-pull")]
    async fn pull_image(&self, image_url: &str, bundle_path: &str) -> Result<String> {
        use std::path::Path;

        let image_id = self
            .image_client
            .lock()
            .await
            .pull_image(image_url, Path::new(bundle_path), &None, &None)
            .await
            .map_err(|e| Error::ImagePull { source: e })?;
        Ok(image_id)
    }

    #[cfg(not(feature = "image-pull"))]
    async fn pull_image(&self, _image_url: &str, _bundle_path: &str) -> Result<String> {
        Err(Error::ImagePull {
            source: anyhow::anyhow!(
                "image-pull not enabled. Try to add `image-pull` feature when building CDH."
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "image-pull")]
    #[tokio::test]
    async fn test_pull_image() {
        use crate::{hub::Hub, CdhConfig, DataHub};

        let image = "busybox:latest";
        let cdh_config = CdhConfig::new(None).unwrap();
        let cdh = Hub::new(cdh_config).await.unwrap();
        let r = cdh.pull_image(image, "/tmp/busybox-bundle").await.unwrap();
        println!("{r}");
    }
}
