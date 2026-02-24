// Copyright (c) 2021 IBM Corp.
// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use resource_uri::ResourceUri;
use tokio::fs;
use tracing::warn;

use crate::{Error, Result};

use super::Kbc;

const KEYS_PATH: &str = "/etc/aa-offline_fs_kbc-keys.json";
const RESOURCES_PATH: &str = "/etc/aa-offline_fs_kbc-resources.json";

pub struct OfflineFsKbc {
    /// Stored resources, loaded from file system
    resources: HashMap<String, Vec<u8>>,
}

#[async_trait]
impl Kbc for OfflineFsKbc {
    async fn get_resource(&mut self, rid: ResourceUri) -> Result<Vec<u8>> {
        let resource_path = rid.resource_path();
        self.resources
            .get(&resource_path)
            .ok_or(Error::KbsClientError(format!(
                "offline-fs-kbc: resource not found {resource_path}"
            )))
            .cloned()
    }
}

impl OfflineFsKbc {
    pub async fn new() -> Result<Self> {
        let mut res = Self {
            resources: HashMap::new(),
        };

        res.init_with_file(KEYS_PATH).await?;
        res.init_with_file(RESOURCES_PATH).await?;

        Ok(res)
    }

    async fn init_with_file(&mut self, path: &str) -> Result<()> {
        let file = match fs::read(path).await {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to read file {path} to init offline-fs-kbc: {e:?}");
                return Ok(());
            }
        };

        let map: HashMap<String, String> = serde_json::from_slice(&file).map_err(|e| {
            Error::KbsClientError(format!(
                "offline-fs-kbc: illegal resource file {path}: {e:?}"
            ))
        })?;
        for (k, v) in &map {
            let value = STANDARD.decode(v).map_err(|e| {
                Error::KbsClientError(format!(
                    "offline-fs-kbc: decode value from file {path} failed: {e:?}"
                ))
            })?;
            if self.resources.insert(k.to_owned(), value).is_some() {
                warn!("detected duplicated resource definition {k} in file {path} when initializing offline-fs-kbc");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use resource_uri::ResourceUri;
    use rstest::rstest;

    use crate::plugins::kbs::{offline_fs::OfflineFsKbc, Kbc};

    #[rstest]
    #[tokio::test]
    #[case("default/key/1", b"key1")]
    async fn test_get_key(#[case] key: &str, #[case] value: &[u8]) {
        let mut kbc = OfflineFsKbc {
            resources: [(key.to_string(), value.to_vec())]
                .iter()
                .cloned()
                .collect(),
        };

        let rid = ResourceUri::try_from(&format!("kbs:///{key}")[..]).unwrap();
        assert_eq!(
            kbc.get_resource(rid).await.expect("get key failed")[..],
            *value
        );
    }
}
