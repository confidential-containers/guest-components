// Copyright (c) 2021 IBM Corp.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{
    common::crypto,
    kbc_modules::{KbcCheckInfo, KbcInterface, ResourceDescription},
};
pub mod common;
use common::*;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use zeroize::Zeroizing;

use super::AnnotationPacket;

const KEYS_PATH: &str = "/etc/aa-offline_fs_kbc-keys.json";
const RESOURCES_PATH: &str = "/etc/aa-offline_fs_kbc-resources.json";

pub struct OfflineFsKbc {
    // KBS info for compatibility; unused
    kbs_info: HashMap<String, String>,
    // Stored keys, loaded from file system; load might fail
    keys: Result<Keys>,
    // Stored resources, loaded from file system; load might fail
    resources: Result<Resources>,
}

#[async_trait]
impl KbcInterface for OfflineFsKbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Ok(KbcCheckInfo {
            kbs_info: self.kbs_info.clone(),
        })
    }

    async fn decrypt_payload(&mut self, annotation_packet: AnnotationPacket) -> Result<Vec<u8>> {
        let key = self.get_key(&annotation_packet.kid).await?;
        let plain_payload = crypto::decrypt(
            key,
            base64::decode(annotation_packet.wrapped_data)?,
            base64::decode(annotation_packet.iv)?,
            &annotation_packet.wrap_type,
        )?;

        Ok(plain_payload)
    }

    async fn get_resource(&mut self, description: &str) -> Result<Vec<u8>> {
        let desc: ResourceDescription = serde_json::from_str::<ResourceDescription>(description)?;
        let resources = self.resources.as_ref().map_err(|e| anyhow!("{}", e))?;
        let resource = resources
            .get(desc.name.as_str())
            .ok_or_else(|| anyhow!("Received unknown resource name: {}", desc.name.as_str()))?;
        Ok(resource.to_vec())
    }
}

impl OfflineFsKbc {
    #[allow(clippy::new_without_default)]
    pub fn new() -> OfflineFsKbc {
        OfflineFsKbc {
            kbs_info: HashMap::new(),
            keys: load_keys(KEYS_PATH).map_err(|e| anyhow!("Failed to load keys: {}", e)),
            resources: load_resources(RESOURCES_PATH)
                .map_err(|e| anyhow!("Failed to load resources: {}", e)),
        }
    }

    async fn get_key(&mut self, keyid: &str) -> Result<Zeroizing<Vec<u8>>> {
        let keys = self.keys.as_ref().map_err(|e| anyhow!("{}", e))?;
        let key = keys
            .get(keyid)
            .ok_or_else(|| anyhow!("Received unknown key ID: {}", keyid))?
            .clone();

        let key = Zeroizing::new(key);
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kbc_modules::ResourceName;
    use common::tests::{COSIGNKEY, CREDENTIAL, KEY, KID, POLICYJSON, PUBKEY, SIGSTORECONFIG};

    const WRONG_KEY: &str = "key";

    #[tokio::test]
    async fn test_get_key() {
        let mut kbc = OfflineFsKbc {
            kbs_info: HashMap::new(),
            keys: Ok([(KID.to_string(), KEY.to_vec())].iter().cloned().collect()),
            resources: Ok([].iter().cloned().collect()),
        };

        assert_eq!(&kbc.get_key(KID).await.expect("get key failed")[..], KEY);
        assert!(kbc.get_key(WRONG_KEY).await.is_err());
    }

    #[tokio::test]
    async fn test_get_resource() {
        // Case 1. Get resources from good kbc instance correctly
        let mut kbc = OfflineFsKbc {
            kbs_info: HashMap::new(),
            keys: Ok([(KID.to_string(), KEY.to_vec())].iter().cloned().collect()),
            resources: Ok([
                (
                    ResourceName::Policy.to_string(),
                    POLICYJSON.as_bytes().to_vec(),
                ),
                (
                    ResourceName::SigstoreConfig.to_string(),
                    SIGSTORECONFIG.as_bytes().to_vec(),
                ),
                (
                    ResourceName::GPGPublicKey.to_string(),
                    PUBKEY.as_bytes().to_vec(),
                ),
                (
                    ResourceName::CosignVerificationKey.to_string(),
                    COSIGNKEY.as_bytes().to_vec(),
                ),
                (
                    ResourceName::Credential.to_string(),
                    CREDENTIAL.as_bytes().to_vec(),
                ),
                (
                    ResourceName::Credential.to_string() + "." + "quay.io",
                    CREDENTIAL.as_bytes().to_vec(),
                ),
            ]
            .iter()
            .cloned()
            .collect()),
        };

        let policy_rd = serde_json::to_string(&ResourceDescription {
            name: ResourceName::Policy.to_string(),
            optional: HashMap::new(),
        })
        .unwrap();
        assert_eq!(
            kbc.get_resource(&policy_rd).await.unwrap(),
            POLICYJSON.as_bytes()
        );

        let sigstore_config_rd = serde_json::to_string(&ResourceDescription {
            name: ResourceName::SigstoreConfig.to_string(),
            optional: HashMap::new(),
        })
        .unwrap();
        assert_eq!(
            kbc.get_resource(&sigstore_config_rd).await.unwrap(),
            SIGSTORECONFIG.as_bytes()
        );

        let public_key_rd = serde_json::to_string(&ResourceDescription {
            name: ResourceName::GPGPublicKey.to_string(),
            optional: HashMap::new(),
        })
        .unwrap();
        assert_eq!(
            kbc.get_resource(&public_key_rd).await.unwrap(),
            PUBKEY.as_bytes()
        );

        let cosign_key_rd = serde_json::to_string(&ResourceDescription {
            name: ResourceName::CosignVerificationKey.to_string(),
            optional: HashMap::new(),
        })
        .unwrap();
        assert_eq!(
            kbc.get_resource(&cosign_key_rd).await.unwrap(),
            COSIGNKEY.as_bytes()
        );

        let credential_rd = serde_json::to_string(&ResourceDescription {
            name: ResourceName::Credential.to_string(),
            optional: HashMap::new(),
        })
        .unwrap();
        assert_eq!(
            kbc.get_resource(&credential_rd).await.unwrap(),
            CREDENTIAL.as_bytes()
        );

        // Case 2. Error while get bad resource name from a good kbc instance
        assert!(kbc.get_resource("bad").await.is_err());

        // Case 3. Error while get good resource name from bad kbc instance
        let mut resources_load_failure_kbc = OfflineFsKbc {
            kbs_info: HashMap::new(),
            keys: Ok([(KID.to_string(), KEY.to_vec())].iter().cloned().collect()),
            resources: Err(anyhow!("")),
        };
        let good_policy_rd = serde_json::to_string(&ResourceDescription {
            name: ResourceName::Policy.to_string(),
            optional: HashMap::new(),
        })
        .unwrap();

        assert!(resources_load_failure_kbc
            .get_resource(&good_policy_rd)
            .await
            .is_err());
    }
}
