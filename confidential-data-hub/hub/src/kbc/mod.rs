// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Abstraction for KBCs as a KMS plugin.

#[cfg(feature = "kbs")]
mod cc_kbc;
mod offline_fs;

use std::sync::Arc;

use async_trait::async_trait;
pub use resource_uri::ResourceUri;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::KbcConfig;

#[derive(Error, Debug)]
pub enum KbcError {
    #[error("CC KBC Error: {source}")]
    CcKbcError {
        #[source]
        source: anyhow::Error,
    },

    #[error("Offline FS KBC Error: {source}")]
    OfflineFsKbcError {
        #[source]
        source: anyhow::Error,
    },

    #[error("Malwared Resource URI: {0}")]
    MalwaredResourceUri(String),

    #[error("Unsupported KBC: {0}")]
    UnsupportedKbc(String),
}

pub type Result<T> = std::result::Result<T, KbcError>;

#[async_trait]
pub trait Kbc: Send + Sync {
    async fn get_resource(&mut self, _rid: ResourceUri) -> anyhow::Result<Vec<u8>>;
}

pub enum KbcClient {
    #[cfg(feature = "kbs")]
    Cc(Arc<Mutex<cc_kbc::CcKbc>>),
    OfflineFs(Arc<Mutex<offline_fs::OfflineFsKbc>>),
}

impl KbcClient {
    pub async fn new(kbc_config: &KbcConfig, _aa_socket: &str) -> Result<Self> {
        let kbc_client = match kbc_config {
            #[cfg(feature = "kbs")]
            KbcConfig::Kbs { url, kbs_cert } => KbcClient::Cc(Arc::new(Mutex::new(
                cc_kbc::CcKbc::new(url, kbs_cert.as_ref(), _aa_socket)
                    .await
                    .map_err(|e| KbcError::CcKbcError { source: e })?,
            ))),
            #[cfg(not(feature = "kbs"))]
            KbcConfig::Kbs { .. } => {
                return Err(KbcError::UnsupportedKbc(
                    "`cc_kbc` requires the `kbs` feature to be enabled".into(),
                ));
            }

            KbcConfig::OfflineFs {} => KbcClient::OfflineFs(Arc::new(Mutex::new(
                offline_fs::OfflineFsKbc::new()
                    .await
                    .map_err(|e| KbcError::OfflineFsKbcError { source: e })?,
            ))),
        };

        Ok(kbc_client)
    }

    pub async fn get_resource(&self, name: &str) -> Result<Vec<u8>> {
        let resource_uri = ResourceUri::try_from(name)
            .map_err(|_| KbcError::MalwaredResourceUri(name.to_string()))?;

        match self {
            #[cfg(feature = "kbs")]
            KbcClient::Cc(c) => c
                .lock()
                .await
                .get_resource(resource_uri)
                .await
                .map_err(|e| KbcError::CcKbcError { source: e }),
            KbcClient::OfflineFs(c) => c
                .lock()
                .await
                .get_resource(resource_uri)
                .await
                .map_err(|e| KbcError::OfflineFsKbcError { source: e }),
        }
    }
}
