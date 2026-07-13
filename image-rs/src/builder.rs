// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{path::PathBuf, sync::Arc};

use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::{
    auth::{Auth, AuthError},
    config::ImageConfig,
    image::ImageClient,
    layer_store::LayerStore,
    meta_store::{MetaStore, METAFILE},
    registry::RegistryHandler,
    resource::{ResourceError, ResourceProvider},
    signature::{SignatureError, SignatureValidator},
    snapshots::SnapshotType,
};

pub type BuilderResult<T> = std::result::Result<T, BuilderError>;

#[derive(Error, Debug)]
pub enum BuilderError {
    #[error("Malwared registry configuration: {source}")]
    InvalidRegistryConfiguration {
        #[source]
        source: anyhow::Error,
    },

    #[error("Initialize layer store failed: {source}")]
    InitializeLayerStoreFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("Initialize resource provider failed: {0}")]
    InitializeResourceProviderFailed(#[from] ResourceError),

    #[error("Initialize auth module failed: {0}")]
    InitializeAuthFailed(#[from] AuthError),

    #[error("Initialize signature validator failed: {0}")]
    InitializeSignatureValidatorFailed(#[from] SignatureError),
}

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
    __impl_config!(image_security_policy, Some(image_security_policy), String);
    __impl_config!(sigstore_config_uri, Some(sigstore_config_uri), String);
    __impl_config!(sigstore_config, Some(sigstore_config), String);
    __impl_config!(
        authenticated_registry_credentials_uri,
        Some(authenticated_registry_credentials_uri),
        String
    );
    __impl_config!(
        registry_configuration_uri,
        Some(registry_configuration_uri),
        String
    );

    __impl_config!(max_concurrent_layer_downloads_per_image, usize);

    #[cfg(feature = "keywrap-native")]
    __impl_config!(kbc, String);

    #[cfg(feature = "keywrap-native")]
    __impl_config!(kbs_uri, kbs_uri, String);

    pub async fn build(self) -> BuilderResult<ImageClient> {
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
                info!("getting registry auth from {uri} ...");
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
            None => self
                .config
                .sigstore_config
                .as_ref()
                .map(|cfg| cfg.as_bytes().to_vec()),
        };

        let policy_bytes = match &self.config.image_security_policy_uri {
            Some(uri) => {
                info!("getting image security policy from {uri} ...");
                let cfg_bytes = resource_provider.get_resource(uri).await?;
                Some(cfg_bytes)
            }
            None => self
                .config
                .image_security_policy
                .as_ref()
                .map(|cfg| cfg.as_bytes().to_vec()),
        };

        let signature_validator = match policy_bytes {
            Some(policy) => {
                let signature_validator = SignatureValidator::new(
                    &policy,
                    sigstore_config,
                    &self.config.work_dir,
                    self.config.image_pull_proxy.clone(),
                    self.config.extra_root_certificates.clone(),
                    resource_provider.clone(),
                )
                .await?;
                Some(signature_validator)
            }
            None => {
                warn!("No `image_security_policy` given, thus all images can be pulled by the image client without filtering.");
                None
            }
        };

        let registry_handler = if let Some(config) = &self.config.registry_config {
            info!("using registry configuration from CDH config file");
            Some(
                RegistryHandler::new(config.clone())
                    .map_err(|source| BuilderError::InvalidRegistryConfiguration { source })?,
            )
        } else {
            match &self.config.registry_configuration_uri {
                Some(uri) => {
                    info!("getting registry configuration from {uri} ...");
                    let registry_configuration = resource_provider.get_resource(uri).await?;
                    let registry_handler = RegistryHandler::from_vec(registry_configuration)
                        .map_err(|source| BuilderError::InvalidRegistryConfiguration { source })?;
                    Some(registry_handler)
                }
                None => None,
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

        let snapshot = ImageClient::init_snapshot(
            &self.config.default_snapshot,
            &self.config.work_dir,
            &meta_store,
        );
        info!("Image work directory: {:?}", self.config.work_dir);
        let meta_store = Arc::new(RwLock::new(meta_store));

        let layer_store = LayerStore::new(self.config.work_dir.clone())
            .map_err(|source| BuilderError::InitializeLayerStoreFailed { source })?;

        Ok(ImageClient {
            registry_auth,
            signature_validator,
            registry_handler,
            meta_store,
            snapshot,
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
