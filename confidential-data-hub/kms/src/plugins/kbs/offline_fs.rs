// Copyright (c) 2021 IBM Corp.
// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use resource_uri::ResourceUri;
use tokio::fs;
use tracing::warn;

use crate::{Error, Result};

use super::Kbc;

const KEYS_PATH: &str = "/etc/aa-offline_fs_kbc-keys.json";
const RESOURCES_PATH: &str = "/etc/aa-offline_fs_kbc-resources.json";

/// Environment variable to specify the path to the extra file.
/// Split by ',' (if any) to specify multiple file paths.
const EXTRA_FILE_PATH_ENV_VAR: &str = "OFFLINE_FS_KBC_EXTRA_FILE_PATH";

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

        if let Ok(extra_file_path) = std::env::var(EXTRA_FILE_PATH_ENV_VAR) {
            for path in extra_file_path.split(',') {
                res.init_with_file(path).await?;
            }
        }

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
                warn!(
                    "detected duplicated resource definition {k} in file {path} when initializing offline-fs-kbc"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use resource_uri::ResourceUri;
    use rstest::rstest;

    use crate::plugins::kbs::{Kbc, offline_fs::OfflineFsKbc};

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

    #[tokio::test]
    async fn init_with_missing_file_is_noop() {
        let mut kbc = OfflineFsKbc {
            resources: Default::default(),
        };
        kbc.init_with_file("/no/such/path/resources.json")
            .await
            .expect("missing file must not fail");
        assert!(kbc.resources.is_empty());
    }

    #[tokio::test]
    async fn init_with_malformed_json_returns_error() {
        let f = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(f.path(), b"{ not valid json }")
            .await
            .unwrap();
        let mut kbc = OfflineFsKbc {
            resources: Default::default(),
        };
        assert!(
            kbc.init_with_file(f.path().to_str().unwrap())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn init_with_valid_file_populates_resources() {
        let content = serde_json::json!({
            "default/key/1": STANDARD.encode(b"key1"),
            "default/key/2": STANDARD.encode(b"key2"),
        })
        .to_string();
        let f = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(f.path(), content.as_bytes())
            .await
            .unwrap();
        let mut kbc = OfflineFsKbc {
            resources: Default::default(),
        };
        kbc.init_with_file(f.path().to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(kbc.resources.get("default/key/1").unwrap(), b"key1");
        assert_eq!(kbc.resources.get("default/key/2").unwrap(), b"key2");
    }

    #[tokio::test]
    async fn init_with_duplicate_key_overwrites_without_error() {
        // same file loaded twice — second load overwrites silently
        let content = serde_json::json!({
            "default/key/1": STANDARD.encode(b"value"),
        })
        .to_string();
        let f = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(f.path(), content.as_bytes())
            .await
            .unwrap();
        let mut kbc = OfflineFsKbc {
            resources: Default::default(),
        };
        kbc.init_with_file(f.path().to_str().unwrap())
            .await
            .unwrap();
        kbc.init_with_file(f.path().to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(kbc.resources.len(), 1);
    }
}
