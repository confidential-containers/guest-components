// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{path::PathBuf, sync::Arc};

use log::{info, warn};
use tokio::sync::RwLock;

use crate::{
    auth::Auth,
    config::{ImageConfig, NydusConfig},
    image::ImageClient,
    layer_store::LayerStore,
    meta_store::{MetaStore, METAFILE},
    resource::ResourceProvider,
    signature::SignatureValidator,
    snapshots::SnapshotType,
};

use anyhow::Result;

#[derive(Default)]
pub struct ClientBuilder {
    config: ImageConfig,
}

macro_rules! __impl_config {
    ($name: ident, $type: ident) => {
        pub fn $name(mut self, $name: $type) -> Self {
            self.config.$name = $name;
            self
        }
    };
    ($name: ident, $value: expr, $type: ident) => {
        pub fn $name(mut self, $name: $type) -> Self {
            self.config.$name = $value;
            self
        }
    };
}

impl ClientBuilder {
    __impl_config!(work_dir, PathBuf);
    __impl_config!(default_snapshot, SnapshotType);
    __impl_config!(
        image_security_policy_uri,
        Some(image_security_policy_uri),
        String
    );
    __impl_config!(sigstore_config_uri, Some(sigstore_config_uri), String);
    __impl_config!(
        authenticated_registry_credentials_uri,
        Some(authenticated_registry_credentials_uri),
        String
    );
    __impl_config!(max_concurrent_layer_downloads_per_image, usize);
    __impl_config!(nydus_config, Some(nydus_config), NydusConfig);

    #[cfg(feature = "keywrap-native")]
    __impl_config!(kbc, String);

    #[cfg(feature = "keywrap-native")]
    __impl_config!(kbs_uri, kbs_uri, String);

    pub async fn build(self) -> Result<ImageClient> {
        #[cfg(feature = "keywrap-native")]
        let resource_provider = Arc::new(ResourceProvider::new(
            &self.config.kbc,
            &self.config.kbs_uri,
            &self.config.work_dir,
        )?);

        #[cfg(not(feature = "keywrap-native"))]
        let resource_provider = Arc::new(ResourceProvider::new("", "", &self.config.work_dir)?);

        let registry_auth = match &self.config.authenticated_registry_credentials_uri {
            Some(uri) => {
                let auth_bytes = resource_provider.get_resource(uri).await?;
                let auth = Auth::new(&auth_bytes)?;
                Some(auth)
            }
            None => None,
        };

        let sigstore_config = match &self.config.sigstore_config_uri {
            Some(uri) => {
                let cfg_bytes = resource_provider.get_resource(uri).await?;
                Some(cfg_bytes)
            }
            None => None,
        };

        let signature_validator = match &self.config.image_security_policy_uri {
            Some(uri) => {
                let policy_bytes = resource_provider.get_resource(uri).await?;
                let auth = SignatureValidator::new(
                    &policy_bytes,
                    sigstore_config,
                    &self.config.work_dir,
                    self.config.skip_proxy_ips.clone(),
                    self.config.image_pull_proxy.clone(),
                    self.config.extra_root_certificates.clone(),
                    resource_provider.clone(),
                )
                .await?;
                Some(auth)
            }
            None => {
                warn!("No `image_security_policy_uri` given, thus all images can be pulled by the image client without filtering.");
                None
            }
        };

        let meta_store = match MetaStore::try_from(self.config.work_dir.join(METAFILE).as_path()) {
            Ok(ms) => {
                info!("Existing metadata found. Using previous ones.");
                ms
            }
            Err(_) => {
                info!("Initialize new metadata.");
                MetaStore::default()
            }
        };

        let snapshots = ImageClient::init_snapshots(&self.config.work_dir, &meta_store);

        let meta_store = Arc::new(RwLock::new(meta_store));

        let layer_store = LayerStore::new(self.config.work_dir.clone())?;

        Ok(ImageClient {
            registry_auth,
            signature_validator,
            meta_store,
            snapshots,
            config: self.config,
            layer_store,
        })
    }
}

impl From<ImageConfig> for ClientBuilder {
    fn from(config: ImageConfig) -> Self {
        Self { config }
    }
}
