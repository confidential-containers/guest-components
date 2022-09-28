// Copyright (c) 2021 IBM Corp.
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use base64::decode;
use openssl::symm::Cipher;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

pub type Keys = HashMap<String, Vec<u8>>;
pub type Ciphers = HashMap<String, Cipher>;

#[derive(Serialize, Deserialize)]
pub struct AnnotationPacket {
    // Key ID to manage multiple keys
    pub kid: String,
    // Encrypted key to unwrap (base64-encoded)
    pub wrapped_data: String,
    // Initialisation vector (base64-encoded)
    pub iv: String,
    // Wrap type to specify encryption algorithm and mode
    pub wrap_type: String,
}

pub fn ciphers() -> Ciphers {
    // The sample KBC uses aes-gcm (Rust implementation). The offline file system KBC uses OpenSSL
    // instead to get access to hardware acceleration on more platforms (e.g. s390x). As opposed
    // to aes-gcm, OpenSSL will only allow GCM when using AEAD. Because authentication is not
    // handled here, AEAD cannot be used, therefore, CTR is used instead.
    [(String::from("aes_256_ctr"), Cipher::aes_256_ctr())]
        .iter()
        .cloned()
        .collect()
}

pub fn load_keys(keyfile_name: &str) -> Result<Keys> {
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

pub mod tests {
    pub use super::*;

    pub use base64::encode;
    pub use std::env;
    pub use std::fs;
    pub use std::path::{Path, PathBuf};

    #[allow(dead_code)]
    pub const KID: &str = "foo";
    #[allow(dead_code)]
    pub const KEY: [u8; 32] = *b"passphrasewhichneedstobe32bytes!";

    #[allow(dead_code)]
    pub fn create_keyfile(name: &str) -> PathBuf {
        let temp_dir = env::temp_dir();
        let keyfile_path = Path::new(&temp_dir).join(name);

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
        keyfile_path
    }

    #[test]
    fn test_load_keys() {
        let keyfile_path = create_keyfile("aa-offline_fs_kbc-test_load_keys");
        let keyfile_name = keyfile_path.to_str().unwrap();
        assert_eq!(
            load_keys(keyfile_name).unwrap(),
            [(KID.to_string(), KEY.to_vec())].iter().cloned().collect()
        );

        fs::write(keyfile_path.clone(), "foo").unwrap();
        assert!(load_keys(keyfile_name).is_err());

        fs::remove_file(keyfile_name).unwrap();
    }
}
