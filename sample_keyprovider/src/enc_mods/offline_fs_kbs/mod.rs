// Copyright (c) 2021 IBM Corp.
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod common;
use common::*;

use anyhow::{anyhow, Result};
use base64::encode;
use openssl::symm::encrypt;
use rand::RngCore;

pub fn enc_optsdata_gen_anno(optsdata: &[u8], params: Vec<String>) -> Result<String> {
    let split_params: Vec<&str> = params[0].split(':').collect();
    if split_params.len() != 2 {
        return Err(anyhow!(
            "Failed to parse parameters: {:?}, need keys file path and key ID split by ':'",
            params
        ));
    }
    let (keyfile_name, kid) = (split_params[0], split_params[1]);
    let keys = load_keys(keyfile_name).map_err(|e| anyhow!("Failed to load keys: {}", e))?;
    let key = keys
        .get(kid)
        .ok_or_else(|| anyhow!("Unknown key ID: {}", kid))?;

    let mut iv = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut iv);

    let wrap_type = String::from("aes_256_ctr");
    let cipher = ciphers().get(&wrap_type).unwrap().to_owned();

    let wrapped_data = encrypt(cipher, key, Some(&iv), optsdata)
        .map_err(|e| anyhow!("Failed to encrypt: {}", e))?;
    serde_json::to_string(&AnnotationPacket {
        kid: String::from(kid),
        wrapped_data: encode(wrapped_data),
        iv: encode(iv),
        wrap_type,
    })
    .map_err(|e| anyhow!("Failed to serialize: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::tests::{create_keyfile, KEY, KID};

    use base64::decode;
    use openssl::symm::decrypt;
    use std::fs;

    #[test]
    fn test_enc_optsdata_gen_anno() {
        let data = b"bar";

        let keyfile_path = create_keyfile("aa-offline_fs_kbs-test_enc_optsdata_gen_anno");
        let keyfile_name = keyfile_path.to_str().unwrap();

        let annotation_string =
            enc_optsdata_gen_anno(data, vec![format!("{}:{}", keyfile_name, KID)]).unwrap();
        let annotation: AnnotationPacket = serde_json::from_str(&annotation_string).unwrap();
        assert_eq!(annotation.kid, KID);
        let cipher = ciphers().get(&annotation.wrap_type).unwrap().to_owned();
        let iv = decode(annotation.iv).unwrap();
        let wrapped_data = decode(annotation.wrapped_data).unwrap();
        assert_eq!(
            decrypt(cipher, &KEY, Some(&iv), &wrapped_data).unwrap(),
            data
        );

        assert!(enc_optsdata_gen_anno(data, vec![format!("{}", keyfile_name)]).is_err());
        assert!(
            enc_optsdata_gen_anno(data, vec![format!("{}:{}:{}", keyfile_name, KID, "")]).is_err()
        );

        assert!(enc_optsdata_gen_anno(data, vec![format!("{}:{}", keyfile_name, "baz")]).is_err());

        fs::remove_file(keyfile_name).unwrap();
    }
}
