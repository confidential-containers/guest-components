// Copyright (c) 2021 IBM Corp.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::kbc_modules::{KbcCheckInfo, KbcInterface};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::decode;
use openssl::symm::{decrypt, Cipher};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::process::Command;

const KEYS_PATH: &str = "/sys/kernel/security/secrets/coco/e6f5a162-d67f-4750-a67c-5d065f2a9910";
const SECRET_MODULE_NAME: &str = "efi_secret";
const MODPROBE_PATH: &str = "/usr/sbin/modprobe";
const MOUNT_PATH: &str = "/usr/bin/mount";

type Keys = HashMap<String, Vec<u8>>;
type Ciphers = HashMap<String, Cipher>;

#[derive(Deserialize)]
pub struct AnnotationPacket {
    // Key ID to manage multiple keys
    pub kid: String,
    // Encrypted key to unwrap
    pub wrapped_data: String,
    // Initialisation vector
    pub iv: String,
    // Wrap type to specify encryption algorithm and mode
    pub wrap_type: String,
}

struct SecretKernelModule;

impl SecretKernelModule {
    fn new() -> Result<SecretKernelModule> {
        if !Command::new(MODPROBE_PATH)
            .arg(SECRET_MODULE_NAME)
            .status()?
            .success()
        {
            return Err(anyhow!("Failed to load secret module."));
        }
        Ok(SecretKernelModule {})
    }
}
impl Drop for SecretKernelModule {
    fn drop(&mut self) {
        Command::new(MODPROBE_PATH)
            .arg("-r")
            .arg(SECRET_MODULE_NAME)
            .status()
            .expect("Failed to unload secret module.");
    }
}

pub struct OfflineSevKbc {
    // KBS info for compatibility; unused
    kbs_info: HashMap<String, String>,
    // Stored keys, loaded from file system; load might fail
    keys: Result<Keys>,
    // Known ciphers, corresponding to wrap_type
    ciphers: Ciphers,
}

fn get_ciphers() -> Ciphers {
    // The sample KBC uses aes-gcm (Rust implementation). The offline file system KBC uses OpenSSL
    // instead to get access to hardware acceleration on more platforms (e.g. s390x). As opposed
    // to aes-gcm, OpenSSL will only allow GCM when using AEAD. Because authentication is not
    // handled here, AEAD cannot be used, therefore, CTR is used instead.
    [(String::from("aes_256_ctr"), Cipher::aes_256_ctr())]
        .iter()
        .cloned()
        .collect()
}

#[async_trait]
impl KbcInterface for OfflineSevKbc {
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
        let iv = decode(annotation_packet.iv).map_err(|e| anyhow!("Failed to decode IV: {}", e))?;
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

impl OfflineSevKbc {
    #[allow(clippy::new_without_default)]
    pub fn new() -> OfflineSevKbc {
        OfflineSevKbc {
            kbs_info: HashMap::new(),
            keys: load_keys(KEYS_PATH).map_err(|e| anyhow!("Failed to load keys: {}", e)),
            ciphers: get_ciphers(),
        }
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
        .map(|(k, v)| match decode(v) {
            Ok(key) => Ok((k.clone(), key)),
            Err(_) => Err(anyhow!("Failed to decode key")),
        })
        .collect()
}

fn mount_security_fs() -> Result<()> {
    if !Command::new(MOUNT_PATH)
        .arg("-t")
        .arg("securityfs")
        .arg("securityfs")
        .arg("/sys/kernel/security")
        .status()?
        .success()
    {
        return Err(anyhow!("Failed to mount security fs"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::encode;
    use openssl::symm::encrypt;

    const KID: &str = "foo";
    const KEY: [u8; 32] = *b"passphrasewhichneedstobe32bytes!";

    #[tokio::test]
    async fn test_decrypt_payload() {
        let iv = b"ivmustbe16bytes!";
        let data = b"bar";

        let cipher_key = "aes_256_ctr";
        let cipher = get_ciphers().get(cipher_key).unwrap().to_owned();
        let wrapped_data = encode(encrypt(cipher, &KEY, Some(iv), data).unwrap());
        let encoded_iv = encode(iv);

        let annotation = format!(
            "{{
    \"kid\": \"{}\",
    \"wrapped_data\": {:?},
    \"iv\": {:?},
    \"wrap_type\": \"{}\"
}}",
            KID, wrapped_data, encoded_iv, cipher_key
        );

        let mut kbc = OfflineSevKbc {
            kbs_info: HashMap::new(),
            keys: Ok([(KID.to_string(), KEY.to_vec())].iter().cloned().collect()),
            ciphers: get_ciphers(),
        };

        assert_eq!(kbc.decrypt_payload(&annotation).await.unwrap(), data);

        let invalid_annotation = &annotation[..annotation.len() - 1];
        assert!(kbc.decrypt_payload(invalid_annotation).await.is_err());

        let mut key_load_failure_kbc = OfflineSevKbc {
            kbs_info: HashMap::new(),
            keys: Err(anyhow!("")),
            ciphers: get_ciphers(),
        };
        assert!(key_load_failure_kbc
            .decrypt_payload(&annotation)
            .await
            .is_err());

        let mut unknown_kid_kbc = OfflineSevKbc {
            kbs_info: HashMap::new(),
            keys: Ok([(String::from("baz"), KEY.to_vec())]
                .iter()
                .cloned()
                .collect()),
            ciphers: get_ciphers(),
        };
        assert!(unknown_kid_kbc.decrypt_payload(&annotation).await.is_err());

        // Notice that a valid, but incorrect key does not yield an error
        let mut invalid_key_kbc = OfflineSevKbc {
            kbs_info: HashMap::new(),
            keys: Ok([(
                KID.to_string(),
                b"thispassphraseisntactually32bytes".to_vec(),
            )]
            .iter()
            .cloned()
            .collect()),
            ciphers: get_ciphers(),
        };
        assert!(invalid_key_kbc.decrypt_payload(&annotation).await.is_err());
    }
}
