// Copyright (c) 2021 IBM Corp.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{KbcCheckInfo, KbcInterface};
use base64::{engine::general_purpose::STANDARD, Engine};
use crypto::WrapType;
use sev::*;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::fs;
use zeroize::Zeroizing;

use super::AnnotationPacket;

const KEYS_PATH: &str = "/sys/kernel/security/secrets/coco/e6f5a162-d67f-4750-a67c-5d065f2a9910";

type Keys = HashMap<String, Vec<u8>>;

pub struct OfflineSevKbc {
    // KBS info for compatibility; unused
    kbs_info: HashMap<String, String>,
    // Stored keys, loaded from file system; load might fail
    keys: Result<Keys>,
}

#[async_trait]
impl KbcInterface for OfflineSevKbc {
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
            STANDARD.decode(annotation_packet.wrapped_data)?,
            STANDARD.decode(annotation_packet.iv)?,
            wrap_type,
        )?;

        Ok(plain_payload)
    }
}

impl OfflineSevKbc {
    #[allow(clippy::new_without_default)]
    pub fn new() -> OfflineSevKbc {
        OfflineSevKbc {
            kbs_info: HashMap::new(),
            keys: load_keys(KEYS_PATH).map_err(|e| anyhow!("Failed to load keys: {}", e)),
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

// This function panics if it is unable to delete the secret file after it has been read
// or if it is unable to unload the efi_secret kernel module once it has been loaded.
// Both of these cases could result in exposing the secret.
//
// /sys and /proc should be mounted for this to work correctly.
fn load_keys(keyfile_name: &str) -> Result<Keys> {
    mount_security_fs()?;
    let _secret_module = SecretKernelModule::new()?;

    let keys_json = fs::read_to_string(keyfile_name)?;
    fs::remove_file(keyfile_name).expect("Failed to remove secret file.");

    // Redact parsing errors to avoid side-channels
    let encoded_keys: HashMap<String, String> =
        serde_json::from_str(&keys_json).map_err(|_| anyhow!("Failed to parse keys JSON file"))?;

    encoded_keys
        .iter()
        .map(|(k, v)| match STANDARD.decode(v) {
            Ok(key) => Ok((k.clone(), key)),
            Err(_) => Err(anyhow!("Failed to decode key")),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KID: &str = "foo";
    const KEY: [u8; 32] = *b"passphrasewhichneedstobe32bytes!";
    const WRONG_KEY: &str = "key";

    #[tokio::test]
    async fn test_get_key() {
        let mut kbc = OfflineSevKbc {
            kbs_info: HashMap::new(),
            keys: Ok([(KID.to_string(), KEY.to_vec())].iter().cloned().collect()),
        };

        assert_eq!(&kbc.get_key(KID).await.expect("get key failed")[..], KEY);
        assert!(kbc.get_key(WRONG_KEY).await.is_err());
    }
}
