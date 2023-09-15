// Copyright (c) 2023 Intel
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(feature = "aliyun")]
pub mod alibaba_cloud_oss;

#[cfg(feature = "aliyun")]
use self::alibaba_cloud_oss::oss::Oss;
use crate::{Error, Result};
use log::warn;

#[derive(PartialEq, Clone, Debug)]
pub struct Storage {
    pub driver: String,
    pub driver_options: Vec<String>,
    pub source: String,
    pub fstype: String,
    pub options: Vec<String>,
    pub mount_point: String,
}

impl Storage {
    pub async fn mount(&self) -> Result<String> {
        for driver_option in &self.driver_options {
            let (volumetype, metadata) =
                driver_option
                    .split_once('=')
                    .ok_or(Error::SecureMountFailed(
                        "split by \"=\" failed".to_string(),
                    ))?;

            match volumetype {
                #[cfg(feature = "aliyun")]
                "alibaba-cloud-oss" => {
                    let oss: Oss = serde_json::from_str(metadata).map_err(|e| {
                        Error::SecureMountFailed(format!(
                            "illegal mount info format (json deseralization failed): {e}"
                        ))
                    })?;
                    return oss
                        .mount(self.source.clone(), self.mount_point.clone())
                        .await;
                }
                other => {
                    warn!("skip mount info with unsupported volumetype: {other}");
                }
            };
        }
        Err(Error::SecureMountFailed(
            "illegal mount info as no expected driver_options".to_string(),
        ))
    }
}
