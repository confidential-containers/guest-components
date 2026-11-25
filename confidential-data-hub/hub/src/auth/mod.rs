// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module helps to get confidential resources that will be used
//! by Confidential Data Hub via KBC, i.e. credentials used by KMSes.
//!
//! Note that for some historical reason, we still use paths `kbs` in the codes.
//! But the resources are got via KBC, thus the source can be KBS, or local file /
//! system, s.t. OfflineFs KBC.

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use const_format::concatcp;
use tokio::fs;
use tracing::debug;

use crate::{
    hub::{Hub, CDH_BASE_DIR},
    kbc::KbcClient,
    Error, Result,
};

/// Directory for KBC resources (credentials, etc.) fetched at init, see the `[[credentials]]`
/// sections in CDH's `config.toml` file, for an example, see `example.config.toml`.
const KBS_RESOURCE_STORAGE_DIR: &str = concatcp!(CDH_BASE_DIR, "/kbs");

impl Hub {
    pub(crate) async fn init_kbs_resources(
        credentials: &HashMap<String, String>,
        kbc_client: Arc<KbcClient>,
    ) -> Result<()> {
        // check the validity of the credential paths.
        for k in credentials.keys() {
            if !is_path_valid(k) {
                return Err(Error::InitializationFailed(format!(
                    "illegal path to put credential : {k}"
                )));
            }
        }

        fs::create_dir_all(KBS_RESOURCE_STORAGE_DIR)
            .await
            .map_err(|e| {
                Error::InitializationFailed(format!(
                    "Create {KBS_RESOURCE_STORAGE_DIR} dir failed {e:?}."
                ))
            })?;

        for (k, v) in credentials {
            let content = kbc_client.get_resource(v).await.map_err(|e| {
                Error::InitializationFailed(format!("kbs client get resource failed: {e:?}"))
            })?;

            let target_path = PathBuf::from(k);

            debug!(
                "Get config item {v} from KBS and put to {}",
                target_path.as_os_str().to_string_lossy()
            );

            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent).await.map_err(|e| {
                    Error::InitializationFailed(format!("create dir {parent:?} failed: {e:?}"))
                })?;
            }

            fs::write(target_path, content).await.map_err(|e| {
                Error::InitializationFailed(format!("write kbs initialization file failed: {e:?}"))
            })?;
        }

        Ok(())
    }
}

/// This function helps to check if a path is valid, including:
/// - it does not have any `..`
/// - it does not have any `.`
/// - it starts with [`KBS_RESOURCE_STORAGE_DIR`]
///
/// The checks are done avoid unexpected path attacks, such as putting a file
/// to random path in the guest.
fn is_path_valid(path: &str) -> bool {
    path.starts_with(KBS_RESOURCE_STORAGE_DIR) && !path.split('/').any(|it| it == ".." || it == ".")
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{is_path_valid, KBS_RESOURCE_STORAGE_DIR};

    #[rstest]
    #[case("/etc/config.toml".into(), false)]
    #[case(format!("{KBS_RESOURCE_STORAGE_DIR}/../../config.toml",), false)]
    #[case(format!("{KBS_RESOURCE_STORAGE_DIR}/kms-credential/../../../config.toml"), false)]
    #[case(format!("{KBS_RESOURCE_STORAGE_DIR}/kms-credential/./config.toml"), false)]
    #[case(format!("{KBS_RESOURCE_STORAGE_DIR}/kms-credential/aliyun/config.toml"), true)]
    fn path_valid(#[case] path: String, #[case] res: bool) {
        assert_eq!(is_path_valid(&path), res);
    }
}
