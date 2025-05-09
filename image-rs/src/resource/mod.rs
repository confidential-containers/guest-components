// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module helps to fetch resource using different
//! protocols. Different resources can be marked in a
//! specific uri. Now, it supports the following:
//!
//! - `file://`: from the local filesystem
//! - `kbs://`: using secure channel to fetch from the KBS

use std::{io, path::Path};

use anyhow::anyhow;
use thiserror::Error;
use tokio::fs;

#[cfg(feature = "kbs")]
pub mod kbs;

pub type ResourceResult<T> = std::result::Result<T, ResourceError>;

#[derive(Error, Debug)]
pub enum ResourceError {
    #[error("Failed to establish secure channel: {source}")]
    EstablishSecureChannel {
        #[source]
        source: anyhow::Error,
    },

    #[error("Get resource failed: {source}")]
    GetResource {
        #[source]
        source: anyhow::Error,
    },

    #[error("`kbs` feature not enabled, cannot support fetch resource")]
    KbsFeatureNotEnabled,

    #[error("Resource URI scheme `{0}` not supported")]
    UnsupportedScheme(String),

    #[error("Failed to read local file")]
    ReadLocalFile {
        #[source]
        source: io::Error,
    },
}

#[derive(Default)]
pub struct ResourceProvider {
    #[cfg(feature = "kbs")]
    secure_channel: kbs::SecureChannel,
}

impl ResourceProvider {
    pub fn new(_kbc_name: &str, _kbs_uri: &str, _work_dir: &Path) -> ResourceResult<Self> {
        #[cfg(feature = "kbs")]
        let secure_channel = kbs::SecureChannel::new(_kbc_name, _kbs_uri, _work_dir)
            .map_err(|source| ResourceError::EstablishSecureChannel { source })?;
        Ok(Self {
            #[cfg(feature = "kbs")]
            secure_channel,
        })
    }

    /// This is a public API to retrieve resources. The input parameter `uri` should be
    /// a URL. For example `file://...`
    /// The resource will be retrieved in different ways due to different schemes.
    /// If no scheme is given, it will by default use `file://` to look for the file
    /// in the local filesystem.
    pub async fn get_resource(&self, uri: &str) -> ResourceResult<Vec<u8>> {
        let uri = if uri.contains("://") {
            uri.to_string()
        } else {
            "file://".to_owned() + uri
        };

        let url = url::Url::parse(&uri).map_err(|e| ResourceError::GetResource {
            source: anyhow!("Failed to parse resource uri: {:?}", e),
        })?;
        match url.scheme() {
            "kbs" => {
                #[cfg(feature = "kbs")]
                {
                    self.secure_channel
                        .get_resource(&uri)
                        .await
                        .map_err(|source| ResourceError::GetResource { source })
                }

                #[cfg(not(feature = "kbs"))]
                {
                    Err(ResourceError::KbsFeatureNotEnabled)
                }
            }
            "file" => {
                let path = url.path();
                let content = fs::read(path)
                    .await
                    .map_err(|source| ResourceError::ReadLocalFile { source })?;
                Ok(content)
            }
            others => Err(ResourceError::UnsupportedScheme(others.into())),
        }
    }
}
