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

use anyhow::*;
use tokio::fs;

#[cfg(feature = "kbs")]
pub mod kbs;

#[derive(Default)]
pub struct ResourceProvider {
    #[cfg(feature = "kbs")]
    secure_channel: kbs::SecureChannel,
}

impl ResourceProvider {
    pub fn new(_kbc_name: &str, _kbs_uri: &str) -> Result<Self> {
        #[cfg(feature = "kbs")]
        let secure_channel = kbs::SecureChannel::new(_kbc_name, _kbs_uri)?;
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
    pub async fn get_resource(&self, uri: &str) -> Result<Vec<u8>> {
        let uri = if uri.contains("://") {
            uri.to_string()
        } else {
            "file://".to_owned() + uri
        };

        let url = url::Url::parse(&uri).map_err(|e| anyhow!("Failed to parse: {:?}", e))?;
        match url.scheme() {
            "kbs" => {
                #[cfg(feature = "kbs")]
                {
                    self.secure_channel.get_resource(&uri).await
                }

                #[cfg(not(feature = "kbs"))]
                {
                    bail!(
                        "`kbs` feature not enabled, cannot support fetch resource uri {}",
                        uri
                    )
                }
            }
            "file" => {
                let path = url.path();
                let content = fs::read(path).await?;
                Ok(content)
            }
            others => bail!("not support scheme {}", others),
        }
    }
}
