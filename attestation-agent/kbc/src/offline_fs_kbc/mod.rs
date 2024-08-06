// Copyright (c) 2021 IBM Corp.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{KbcCheckInfo, KbcInterface};

pub mod common;
use common::*;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::Engine;
use crypto::WrapType;
use resource_uri::ResourceUri;
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
        let key = self.get_key(&annotation_packet.kid.resource_path()).await?;
        let wrap_type = WrapType::try_from(&annotation_packet.wrap_type[..])?;
        let plain_payload = crypto::decrypt(
            key,
            base64::engine::general_purpose::STANDARD.decode(annotation_packet.wrapped_data)?,
            base64::engine::general_purpose::STANDARD.decode(annotation_packet.iv)?,
            wrap_type,
        )?;

        Ok(plain_payload)
    }

    async fn get_resource(&mut self, rid: ResourceUri) -> Result<Vec<u8>> {
        let resource_path = rid.resource_path();
        let resources = self.resources.as_ref().map_err(|e| anyhow!("{}", e))?;
        let resource = resources
            .get(resource_path.as_str())
            .ok_or_else(|| anyhow!("Received unknown resource name: {}", resource_path.as_str()))?;
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
    use crate::{resource_path, tests::ResourcePath};

    use super::{common::tests::KBS_URI_PREFIX, *};
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

    fn kbc_instance() -> OfflineFsKbc {
        OfflineFsKbc {
            kbs_info: HashMap::new(),
            keys: Err(anyhow!("no keys")),
            resources: Ok([
                (
                    resource_path!(ResourcePath::Policy),
                    POLICYJSON.as_bytes().to_vec(),
                ),
                (
                    resource_path!(ResourcePath::SigstoreConfig),
                    SIGSTORECONFIG.as_bytes().to_vec(),
                ),
                (
                    resource_path!(ResourcePath::GPGPublicKey),
                    PUBKEY.as_bytes().to_vec(),
                ),
                (
                    resource_path!(ResourcePath::CosignVerificationKey),
                    COSIGNKEY.as_bytes().to_vec(),
                ),
                (
                    resource_path!(ResourcePath::Credential),
                    CREDENTIAL.as_bytes().to_vec(),
                ),
            ]
            .iter()
            .cloned()
            .collect()),
        }
    }

    #[rstest::rstest]
    // Case 1. Get resources from good kbc instance correctly
    #[case(true, ResourcePath::Policy.as_ref(), POLICYJSON)]
    #[case(true, ResourcePath::SigstoreConfig.as_ref(), SIGSTORECONFIG)]
    #[case(true, ResourcePath::GPGPublicKey.as_ref(), PUBKEY)]
    #[case(true, ResourcePath::CosignVerificationKey.as_ref(), COSIGNKEY)]
    #[case(true, ResourcePath::Credential.as_ref(), CREDENTIAL)]
    // Case 2. Error while get bad resource name from a good kbc instance
    #[case(false, "kbs:///default/credential/not-existed", "")]
    #[tokio::test]
    async fn test_get_resource(
        #[case] success: bool,
        #[case] resource_id: &str,
        #[case] resource_content: &str,
    ) {
        let mut kbc = kbc_instance();
        let rid = ResourceUri::try_from(resource_id).unwrap();

        let res = kbc.get_resource(rid).await;
        if success {
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), resource_content.as_bytes());
        } else {
            assert!(res.is_err());
        }
    }
}
