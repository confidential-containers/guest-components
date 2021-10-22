// Copyright (c) 2021 IBM Corp.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::kbc_modules::{KbcCheckInfo, KbcInterface};
pub mod common;
use common::*;

use anyhow::{anyhow, Result};
use base64::decode;
use openssl::symm::decrypt;
use std::collections::HashMap;

const KEYS_PATH: &str = "/etc/aa-offline_fs_kbc-keys.json";

pub struct OfflineFsKbc {
    // KBS info for compatibility; unused
    kbs_info: HashMap<String, String>,
    // Stored keys, loaded from file system; load might fail
    keys: Result<Keys>,
    // Known ciphers, corresponding to wrap_type
    ciphers: Ciphers,
}

impl KbcInterface for OfflineFsKbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Ok(KbcCheckInfo {
            kbs_info: self.kbs_info.clone(),
        })
    }

    fn decrypt_payload(&mut self, annotation: &str) -> Result<Vec<u8>> {
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
}

impl OfflineFsKbc {
    #[allow(clippy::new_without_default)]
    pub fn new() -> OfflineFsKbc {
        OfflineFsKbc {
            kbs_info: HashMap::new(),
            keys: load_keys(KEYS_PATH).map_err(|e| anyhow!("Failed to load keys: {}", e)),
            ciphers: ciphers(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::tests::{KEY, KID};

    use base64::encode;
    use openssl::symm::encrypt;

    #[test]
    fn test_decrypt_payload() {
        let iv = b"ivmustbe16bytes!";
        let data = b"bar";

        let cipher_key = "aes_256_ctr";
        let cipher = ciphers().get(cipher_key).unwrap().to_owned();
        let wrapped_data = encode(encrypt(cipher, &KEY, Some(iv), data).unwrap());
        let encoded_iv = encode(iv);

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
        };

        assert_eq!(kbc.decrypt_payload(&annotation).unwrap(), data);

        let invalid_annotation = &annotation[..annotation.len() - 1];
        assert!(kbc.decrypt_payload(invalid_annotation).is_err());

        let mut key_load_failure_kbc = OfflineFsKbc {
            kbs_info: HashMap::new(),
            keys: Err(anyhow!("")),
            ciphers: ciphers(),
        };
        assert!(key_load_failure_kbc.decrypt_payload(&annotation).is_err());

        let mut unknown_kid_kbc = OfflineFsKbc {
            kbs_info: HashMap::new(),
            keys: Ok([(String::from("baz"), KEY.to_vec())]
                .iter()
                .cloned()
                .collect()),
            ciphers: ciphers(),
        };
        assert!(unknown_kid_kbc.decrypt_payload(&annotation).is_err());

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
        };
        assert!(invalid_key_kbc.decrypt_payload(&annotation).is_err());
    }
}
