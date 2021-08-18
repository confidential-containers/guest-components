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

// KBS specific packet
#[derive(Serialize, Deserialize, Debug)]
pub struct AnnotationPacket {
    // The access information of KBS is passed to KBC module through annotation.
    // key_url is used as an example here.
    pub key_url: String,
    pub wrapped_key: Vec<u8>,
    pub wrap_type: String,
}

pub struct SampleKbc {
    encrypted_payload: Vec<u8>,
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
        // Parse the annotation, and obtain the access information of KBS and the field content to be decrypted.
        let annotation_packet: AnnotationPacket = serde_json::from_str(annotation)?;
        self.encrypted_payload = annotation_packet.wrapped_key;

        let cipher_text: &Vec<u8> = &self.encrypted_payload;
        let decrypting_key = Key::from_slice(b"passphrasewhichneedstobe32bytes!");
        let cipher = Aes256Gcm::new(decrypting_key);
        let nonce = Nonce::from_slice(b"unique nonce");

        let plain_text = cipher
            .decrypt(nonce, cipher_text.as_ref())
            .map_err(|e| anyhow!("Decrypt failed: {}", e))?;

        Ok(plain_text)
    }
}

impl SampleKbc {
    pub fn new(kbs_uri: String) -> SampleKbc {
        let mut kbs_info: HashMap<String, String> = HashMap::new();
        kbs_info.insert("kbs_uri".to_string(), kbs_uri);
        SampleKbc {
            encrypted_payload: vec![],
            kbs_info: kbs_info,
        }
    }
}
