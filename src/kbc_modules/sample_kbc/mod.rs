// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::kbc_modules::{KbcCheckInfo, KbcInterface};

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const HARDCODED_KEY: &'static [u8] = &[
    217, 155, 119, 5, 176, 186, 122, 22, 130, 149, 179, 163, 54, 114, 112, 176, 221, 155, 55, 27,
    245, 20, 202, 139, 155, 167, 240, 163, 55, 17, 218, 234,
];

// KBS specific packet
#[derive(Serialize, Deserialize, Debug)]
pub struct AnnotationPacket {
    // This is an example annotation packet format.
    pub kid: String,
    pub wrapped_data: Vec<u8>,
    pub iv: Vec<u8>,
    pub wrap_type: String,
}

pub struct SampleKbc {
    kbs_info: HashMap<String, String>,
}

// As a KBS client for attestation-agent,
// it must implement KbcInterface trait.
impl KbcInterface for SampleKbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Ok(KbcCheckInfo {
            kbs_info: self.kbs_info.clone(),
        })
    }

    fn decrypt_payload(&mut self, annotation: &str) -> Result<Vec<u8>> {
        let annotation_packet: AnnotationPacket = serde_json::from_str(annotation)?;
        let encrypted_payload: Vec<u8> = annotation_packet.wrapped_data;

        let plain_text = decrypt(&encrypted_payload, HARDCODED_KEY, &annotation_packet.iv)?;

        Ok(plain_text)
    }
}

impl SampleKbc {
    pub fn new(kbs_uri: String) -> SampleKbc {
        let mut kbs_info: HashMap<String, String> = HashMap::new();
        kbs_info.insert("kbs_uri".to_string(), kbs_uri);
        SampleKbc { kbs_info: kbs_info }
    }
}

fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let decrypting_key = Key::from_slice(key);
    let cipher = Aes256Gcm::new(decrypting_key);
    let nonce = Nonce::from_slice(iv);
    let plain_text = cipher
        .decrypt(nonce, encrypted_data.as_ref())
        .map_err(|e| anyhow!("Decrypt failed: {:?}", e))?;

    Ok(plain_text)
}
