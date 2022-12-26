// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::common::crypto::{decrypt, WrapType};
use crate::kbc_modules::{KbcCheckInfo, KbcInterface, ResourceDescription, ResourceName};

use anyhow::*;
use async_trait::async_trait;
use std::collections::HashMap;
use std::str::FromStr;
use zeroize::Zeroizing;

use super::AnnotationPacket;

const HARDCODED_KEY: &[u8] = &[
    217, 155, 119, 5, 176, 186, 122, 22, 130, 149, 179, 163, 54, 114, 112, 176, 221, 155, 55, 27,
    245, 20, 202, 139, 155, 167, 240, 163, 55, 17, 218, 234,
];

pub struct SampleKbc {
    kbs_info: HashMap<String, String>,
}

// As a KBS client for attestation-agent,
// it must implement KbcInterface trait.
#[async_trait]
impl KbcInterface for SampleKbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Ok(KbcCheckInfo {
            kbs_info: self.kbs_info.clone(),
        })
    }

    async fn decrypt_payload(&mut self, annotation_packet: AnnotationPacket) -> Result<Vec<u8>> {
        let key = Zeroizing::new(HARDCODED_KEY.to_vec());
        let plain_text = decrypt(
            key,
            base64::decode(annotation_packet.wrapped_data)?,
            base64::decode(annotation_packet.iv)?,
            WrapType::Aes256Gcm.as_ref(),
        )?;

        Ok(plain_text)
    }

    async fn get_resource(&mut self, description: &str) -> Result<Vec<u8>> {
        let desc: ResourceDescription = serde_json::from_str::<ResourceDescription>(description)?;

        match ResourceName::from_str(desc.name.as_str()) {
            Result::Ok(ResourceName::Policy) => {
                Ok(std::include_str!("policy.json").as_bytes().to_vec())
            }
            Result::Ok(ResourceName::SigstoreConfig) => {
                Ok(std::include_str!("sigstore_config.yaml")
                    .as_bytes()
                    .to_vec())
            }
            Result::Ok(ResourceName::GPGPublicKey) => {
                Ok(std::include_str!("pubkey.gpg").as_bytes().to_vec())
            }
            Result::Ok(ResourceName::CosignVerificationKey) => {
                Ok(std::include_str!("cosign.pub").as_bytes().to_vec())
            }
            Result::Ok(ResourceName::Credential) => {
                Ok(std::include_str!("auth.json").as_bytes().to_vec())
            }
            _ => Err(anyhow!("Unknown resource name")),
        }
    }
}

impl SampleKbc {
    pub fn new(kbs_uri: String) -> SampleKbc {
        let mut kbs_info: HashMap<String, String> = HashMap::new();
        kbs_info.insert("kbs_uri".to_string(), kbs_uri);
        SampleKbc { kbs_info }
    }
}
