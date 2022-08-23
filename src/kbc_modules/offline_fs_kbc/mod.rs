// Copyright (c) 2021 IBM Corp.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::kbc_modules::{KbcCheckInfo, KbcInterface, ResourceDescription};
pub mod common;
use common::*;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::decode;
use openssl::symm::decrypt;
use std::collections::HashMap;

const KEYS_PATH: &str = "/etc/aa-offline_fs_kbc-keys.json";
const RESOURCES_PATH: &str = "/etc/aa-offline_fs_kbc-resources.json";

pub struct OfflineFsKbc {
    // KBS info for compatibility; unused
    kbs_info: HashMap<String, String>,
    // Stored keys, loaded from file system; load might fail
    keys: Result<Keys>,
    // Known ciphers, corresponding to wrap_type
    ciphers: Ciphers,
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

    async fn decrypt_payload(&mut self, annotation: &str) -> Result<Vec<u8>> {
        let annotation_packet: AnnotationPacket = serde_json::from_str(annotation)
            .map_err(|e| anyhow!("Failed to parse annotation: {}", e))?;
        let kid = annotation_packet.kid;
        let keys = self.keys.as_ref().map_err(|e| anyhow!("{}", e))?;
        let key = keys
            .get(&kid)
            .ok_or_else(|| anyhow!("Received unknown key ID: {}", kid))?;
        let iv = decode(annotation_packet.iv)
            .map_err(|e| anyhow!("Failed to decode initialization vector: {}", e))?;
        let wrapped_data = decode(annotation_packet.wrapped_data)
            .map_err(|e| anyhow!("Failed to decode wrapped key: {}", e))?;
        let wrap_type = annotation_packet.wrap_type;

        let cipher = self
            .ciphers
            .get(&wrap_type)
            .ok_or_else(|| anyhow!("Received unknown wrap type: {}", wrap_type))?;
        // Redact decryption errors to avoid oracles
        decrypt(*cipher, key, Some(&iv), &wrapped_data).map_err(|_| anyhow!("Failed to decrypt"))
    }

    async fn get_resource(&mut self, description: String) -> Result<Vec<u8>> {
        let desc: ResourceDescription =
            serde_json::from_str::<ResourceDescription>(description.as_str())?;
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
            ciphers: ciphers(),
            resources: load_resources(RESOURCES_PATH)
                .map_err(|e| anyhow!("Failed to load resources: {}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kbc_modules::ResourceName;
    use common::tests::{KEY, KID, POLICYJSON, PUBKEY, SIGSTORECONFIG};

    use base64;
    use openssl::symm::encrypt;

    #[tokio::test]
    async fn test_decrypt_payload() {
        let iv = b"ivmustbe16bytes!";
        let data = b"bar";

        let cipher_key = "aes_256_ctr";
        let cipher = ciphers().get(cipher_key).unwrap().to_owned();
        let wrapped_data = base64::encode(encrypt(cipher, &KEY, Some(iv), data).unwrap());
        let encoded_iv = base64::encode(iv);

        let annotation = format!(
            "{{
    \"kid\": \"{}\",
    \"wrapped_data\": \"{}\",
    \"iv\": \"{}\",
    \"wrap_type\": \"{}\"
}}",
            KID, wrapped_data, encoded_iv, cipher_key
        );

        let mut kbc = OfflineFsKbc {
            kbs_info: HashMap::new(),
            keys: Ok([(KID.to_string(), KEY.to_vec())].iter().cloned().collect()),
            ciphers: ciphers(),
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
            ]
            .iter()
            .cloned()
            .collect()),
        };

        assert_eq!(kbc.decrypt_payload(&annotation).await.unwrap(), data);

        let invalid_annotation = &annotation[..annotation.len() - 1];
        assert!(kbc.decrypt_payload(invalid_annotation).await.is_err());

        let mut key_load_failure_kbc = OfflineFsKbc {
            kbs_info: HashMap::new(),
            keys: Err(anyhow!("")),
            ciphers: ciphers(),
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
            ]
            .iter()
            .cloned()
            .collect()),
        };
        assert!(key_load_failure_kbc
            .decrypt_payload(&annotation)
            .await
            .is_err());

        let mut unknown_kid_kbc = OfflineFsKbc {
            kbs_info: HashMap::new(),
            keys: Ok([(String::from("baz"), KEY.to_vec())]
                .iter()
                .cloned()
                .collect()),
            ciphers: ciphers(),
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
            ]
            .iter()
            .cloned()
            .collect()),
        };
        assert!(unknown_kid_kbc.decrypt_payload(&annotation).await.is_err());

        // Notice that a valid, but incorrect key does not yield an error
        let mut invalid_key_kbc = OfflineFsKbc {
            kbs_info: HashMap::new(),
            keys: Ok([(
                KID.to_string(),
                b"thispassphraseisntactually32bytes".to_vec(),
            )]
            .iter()
            .cloned()
            .collect()),
            ciphers: ciphers(),
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
            ]
            .iter()
            .cloned()
            .collect()),
        };
        assert!(invalid_key_kbc.decrypt_payload(&annotation).await.is_err());
    }

    #[tokio::test]
    async fn test_get_resource() {
        // Case 1. Get resources from good kbc instance correctly
        let mut kbc = OfflineFsKbc {
            kbs_info: HashMap::new(),
            keys: Ok([(KID.to_string(), KEY.to_vec())].iter().cloned().collect()),
            ciphers: ciphers(),
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
            kbc.get_resource(policy_rd).await.unwrap(),
            POLICYJSON.as_bytes()
        );

        let sigstore_config_rd = serde_json::to_string(&ResourceDescription {
            name: ResourceName::SigstoreConfig.to_string(),
            optional: HashMap::new(),
        })
        .unwrap();
        assert_eq!(
            kbc.get_resource(sigstore_config_rd).await.unwrap(),
            SIGSTORECONFIG.as_bytes()
        );

        let public_key_rd = serde_json::to_string(&ResourceDescription {
            name: ResourceName::GPGPublicKey.to_string(),
            optional: HashMap::new(),
        })
        .unwrap();
        assert_eq!(
            kbc.get_resource(public_key_rd).await.unwrap(),
            PUBKEY.as_bytes()
        );

        // Case 2. Error while get bad resource name from a good kbc instance
        assert!(kbc.get_resource("bad".to_string()).await.is_err());

        // Case 3. Error while get good resource name from bad kbc instance
        let mut resources_load_failure_kbc = OfflineFsKbc {
            kbs_info: HashMap::new(),
            keys: Ok([(KID.to_string(), KEY.to_vec())].iter().cloned().collect()),
            ciphers: ciphers(),
            resources: Err(anyhow!("")),
        };
        let good_policy_rd = serde_json::to_string(&ResourceDescription {
            name: ResourceName::Policy.to_string(),
            optional: HashMap::new(),
        })
        .unwrap();

        assert!(resources_load_failure_kbc
            .get_resource(good_policy_rd)
            .await
            .is_err());
    }
}
