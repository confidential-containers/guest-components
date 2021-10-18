// Copyright (c) 2021 IBM Corp.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::kbc_modules::{KbcCheckInfo, KbcInterface};

use anyhow::{anyhow, Result};
use base64::decode;
use openssl::symm::{decrypt, Cipher};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

const KEYS_PATH: &str = "/etc/aa-offline_fs_kbc-keys.json";

type Keys = HashMap<String, Vec<u8>>;
type Ciphers = HashMap<String, Cipher>;

#[derive(Deserialize)]
pub struct AnnotationPacket {
    // Key ID to manage multiple keys
    pub kid: String,
    // Encrypted key to unwrap
    pub wrapped_data: Vec<u8>,
    // Initialisation vector
    pub iv: Vec<u8>,
    // Wrap type to specify encryption algorithm and mode
    pub wrap_type: String,
}

pub struct OfflineFsKbc {
    // KBS info for compatibility; unused
    kbs_info: HashMap<String, String>,
    // Stored keys, loaded from file system; load might fail
    keys: Result<Keys>,
    // Known ciphers, corresponding to wrap_type
    ciphers: Ciphers,
}

fn ciphers() -> Ciphers {
    // The sample KBC uses aes-gcm (Rust implementation). The offline file system KBC uses OpenSSL
    // instead to get access to hardware acceleration on more platforms (e.g. s390x). As opposed
    // to aes-gcm, OpenSSL will only allow GCM when using AEAD. Because authentication is not
    // handled here, AEAD cannot be used, therefore, CTR is used instead.
    [(String::from("aes_256_ctr"), Cipher::aes_256_ctr())]
        .iter()
        .cloned()
        .collect()
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
        let iv = annotation_packet.iv;
        let wrapped_data = annotation_packet.wrapped_data;
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

fn load_keys(keyfile_name: &str) -> Result<Keys> {
    let keys_json = fs::read_to_string(keyfile_name)?;
    // Redact parsing errors to avoid side-channels
    let encoded_keys: HashMap<String, String> =
        serde_json::from_str(&keys_json).map_err(|_| anyhow!("Failed to parse keys JSON file"))?;
    encoded_keys
        .iter()
        .map(|(k, v)| match decode(v) {
            Ok(key) => Ok((k.clone(), key)),
            Err(_) => Err(anyhow!("Failed to decode key")),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::encode;
    use openssl::symm::encrypt;
    use std::env;
    use std::path::Path;

    const KID: &str = "foo";
    const KEY: [u8; 32] = *b"passphrasewhichneedstobe32bytes!";

    #[test]
    fn test_decrypt_payload() {
        let iv = b"ivmustbe16bytes!";
        let data = b"bar";

        let cipher_key = "aes_256_ctr";
        let cipher = ciphers().get(cipher_key).unwrap().to_owned();
        let wrapped_data = encrypt(cipher, &KEY, Some(iv), data).unwrap();

        let annotation = format!(
            "{{
    \"kid\": \"{}\",
    \"wrapped_data\": {:?},
    \"iv\": {:?},
    \"wrap_type\": \"{}\"
}}",
            KID, wrapped_data, iv, cipher_key
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

    #[test]
    fn test_load_keys() {
        let temp_dir = env::temp_dir();
        let keyfile_path = Path::new(&temp_dir).join("aa-offline_fs_kbc-test_load_keys");
        let keyfile_name = keyfile_path.to_str().unwrap();

        fs::write(
            keyfile_path.clone(),
            format!(
                "{{
    \"{}\": \"{}\"
}}",
                KID,
                encode(KEY),
            ),
        )
        .unwrap();
        assert_eq!(
            load_keys(keyfile_name).unwrap(),
            [(KID.to_string(), KEY.to_vec())].iter().cloned().collect()
        );

        fs::write(keyfile_path.clone(), "foo").unwrap();
        assert!(load_keys(keyfile_name.clone()).is_err());

        fs::remove_file(keyfile_name).unwrap()
    }
}
