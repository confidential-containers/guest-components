// Copyright (c) 2023 Intel
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(feature = "aliyun")]
pub mod alibaba_cloud_oss;

use std::{collections::HashMap, str::FromStr};

use crate::Result;

use async_trait::async_trait;

use serde::Deserialize;
use strum::EnumString;

#[derive(EnumString, PartialEq, Debug)]
pub enum Volume {
    #[cfg(feature = "aliyun")]
    #[strum(serialize = "alibaba-cloud-oss")]
    AliOss,
}

/// Indicating a mount point and its parameters.
#[derive(PartialEq, Clone, Debug, Deserialize)]
pub struct Storage {
    /// Driver nameof the mount plugin.
    pub volume_type: String,

    /// A key-value map to provide extra mount settings.
    pub options: HashMap<String, String>,

    /// A flag set to provide extra mount settings. This vector can also
    /// contain string type parameters.
    pub flags: Vec<String>,

    /// The target mount point.
    pub mount_point: String,
}

#[async_trait]
pub trait SecureMount {
    /// Mount the volume to `mount_point` due to the given options.
    async fn mount(
        &self,
        options: &HashMap<String, String>,
        flags: &[String],
        mount_point: &str,
    ) -> Result<()>;
}

impl Storage {
    pub async fn mount(&self) -> Result<String> {
        let volume_type = Volume::from_str(&self.volume_type)?;
        match volume_type {
            #[cfg(feature = "aliyun")]
            Volume::AliOss => {
                let oss = alibaba_cloud_oss::Oss {};
                oss.mount(&self.options, &self.flags, &self.mount_point)
                    .await?;
                Ok(self.mount_point.clone())
            }
        }
    }
}
