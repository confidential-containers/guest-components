// Copyright (c) 2021 IBM Corp.
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use base64::decode;
use std::collections::HashMap;
use std::fs;

pub type Keys = HashMap<String, Vec<u8>>;
pub type Resources = HashMap<String, Vec<u8>>;

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

pub fn load_resources(resources_file_name: &str) -> Result<Resources> {
    let resources_json = fs::read_to_string(resources_file_name)?;
    let encoded_resources: HashMap<String, String> = serde_json::from_str(&resources_json)
        .map_err(|_| anyhow!("Failed to parse resources JSON file"))?;
    encoded_resources
        .iter()
        .map(|(k, v)| match decode(v) {
            Ok(resource) => Ok((k.clone(), resource)),
            Err(e) => Err(anyhow!(
                "Failed to decode resource for {}: {}",
                k,
                e.to_string()
            )),
        })
        .collect()
}

pub mod tests {
    use crate::kbc_modules::tests::ResourcePath;

    pub use super::*;
    pub use base64;
    pub use std::env;
    pub use std::fs;
    pub use std::path::{Path, PathBuf};

    #[allow(dead_code)]
    pub const KID: &str = "foo";
    #[allow(dead_code)]
    pub const KEY: [u8; 32] = *b"passphrasewhichneedstobe32bytes!";
    pub const POLICYJSON: &str = "{\"a\":\"b\"}";
    pub const SIGSTORECONFIG: &str = "sigstore_config:docker";
    pub const PUBKEY: &str = "pubkey";
    pub const COSIGNKEY: &str = "cosignkey";
    pub const CREDENTIAL: &str = "base64-content-of-auth.json";
    #[allow(dead_code)]
    pub const RESOURCES_NAME: &str = "aa-offline_fs_kbc-resources.json";

    pub const KBS_URI_PREFIX: &str = "kbs://example.org/";

    #[macro_export]
    macro_rules! resource_path {
        ($resource: expr) => {
            $resource
                .as_ref()
                .strip_prefix(KBS_URI_PREFIX)
                .unwrap()
                .to_owned()
        };
    }

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
                base64::encode(KEY),
            ),
        )
        .unwrap();
        keyfile_path
    }

    #[allow(dead_code)]
    pub fn create_resources_file(resources_file_path: &Path) {
        let resources_file_content = serde_json::json!({
            resource_path!(ResourcePath::Policy): base64::encode(POLICYJSON.as_bytes()),
            resource_path!(ResourcePath::SigstoreConfig): base64::encode(SIGSTORECONFIG.as_bytes()),
            resource_path!(ResourcePath::GPGPublicKey): base64::encode(PUBKEY.as_bytes()),
            resource_path!(ResourcePath::CosignVerificationKey): base64::encode(COSIGNKEY.as_bytes()),
            resource_path!(ResourcePath::Credential): base64::encode(CREDENTIAL.as_bytes()),
        });

        fs::write(
            resources_file_path,
            serde_json::to_string(&resources_file_content).unwrap(),
        )
        .unwrap();
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

    #[test]
    fn test_load_resources() {
        let temp_dir = env::temp_dir();
        let resources_file_path = &Path::new(&temp_dir).join(RESOURCES_NAME);
        create_resources_file(resources_file_path);
        let resources_file_name = &resources_file_path.to_str().unwrap();
        assert_eq!(
            load_resources(resources_file_name).unwrap(),
            [
                (
                    resource_path!(ResourcePath::Policy),
                    POLICYJSON.as_bytes().to_vec()
                ),
                (
                    resource_path!(ResourcePath::SigstoreConfig),
                    SIGSTORECONFIG.as_bytes().to_vec(),
                ),
                (
                    resource_path!(ResourcePath::GPGPublicKey),
                    PUBKEY.as_bytes().to_vec()
                ),
                (
                    resource_path!(ResourcePath::CosignVerificationKey),
                    COSIGNKEY.as_bytes().to_vec()
                ),
                (
                    resource_path!(ResourcePath::Credential),
                    CREDENTIAL.as_bytes().to_vec()
                ),
            ]
            .iter()
            .cloned()
            .collect()
        );

        fs::write(resources_file_path.clone(), "foo").unwrap();
        assert!(load_resources(resources_file_name).is_err());

        fs::remove_file(resources_file_name).unwrap();
    }
}
