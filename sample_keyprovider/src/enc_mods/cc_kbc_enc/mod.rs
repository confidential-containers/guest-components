// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AeadCore, Aes256Gcm, Key};
use anyhow::*;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AnnotationPacket {
    // Key Resource ID (URL)
    // Format:
    // `cc_kbc://127.0.0.1:8080/test_repo/key/id_1`
    pub kid: String,
    // Encrypted key to unwrap (base64-encoded)
    pub wrapped_data: String,
    // Initialisation vector (base64-encoded)
    pub iv: String,
    // Wrap type to specify encryption algorithm and mode
    pub wrap_type: String,
}

pub fn enc_optsdata_gen_anno(optsdata: &[u8], params: Vec<String>) -> Result<String> {
    let (key_file_path, kid) = params[0].split_once(':').ok_or(anyhow!(
        "Failed to parse parameters: {:?}, need key file path and key URL in KBS split by ':'",
        params
    ))?;

    let key = std::fs::read(key_file_path).map_err(|e| anyhow!("Read Key file failed: {}", e))?;
    let aes_key = Key::<Aes256Gcm>::from_slice(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let cipher = Aes256Gcm::new(aes_key);
    let encrypt_optsdata = cipher
        .encrypt(&nonce, optsdata)
        .map_err(|e| anyhow!("Eecrypt failed: {:?}", e))?;

    let annotation = AnnotationPacket {
        kid: kid.to_string(),
        wrapped_data: base64::encode(encrypt_optsdata),
        iv: base64::encode(nonce.to_vec()),
        wrap_type: "A256GCM".to_string(),
    };

    serde_json::to_string(&annotation).map_err(|_| anyhow!("Serialize annotation failed"))
}
