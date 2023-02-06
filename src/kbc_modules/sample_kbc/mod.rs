// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::common::crypto::{decrypt, WrapType};
use crate::kbc_modules::{KbcCheckInfo, KbcInterface};
use crate::uri::ResourceUri;

use anyhow::*;
use async_trait::async_trait;
use std::collections::HashMap;
use zeroize::Zeroizing;

use super::AnnotationPacket;

const HARDCODED_KEY: &[u8] = &[
    217, 155, 119, 5, 176, 186, 122, 22, 130, 149, 179, 163, 54, 114, 112, 176, 221, 155, 55, 27,
    245, 20, 202, 139, 155, 167, 240, 163, 55, 17, 218, 234,
];

#[derive(AsRefStr, EnumString, Display, Debug, PartialEq, Eq)]
pub enum ResourceType {
    #[strum(serialize = "security-policy")]
    /// image security policy, used to define whether a specific
    /// image can be pulled, or signature verification is needed
    Policy,

    /// used to configure the storage path of public keys used
    /// by simple signing when doing iamge signature verification
    #[strum(serialize = "sigstore-config")]
    SigstoreConfig,

    /// gpg public key used to verify signature of images in
    /// simple signing scheme.
    #[strum(serialize = "gpg-public-config")]
    GPGPublicKey,

    /// public key file used to verify signature of images in
    /// cosign scheme.
    #[strum(serialize = "cosign-public-key")]
    CosignVerificationKey,

    /// container registry auth file, used to provide auth
    /// when accessing a private registry / repository
    #[strum(serialize = "credential")]
    Credential,
}

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

    async fn get_resource(&mut self, rid: ResourceUri) -> Result<Vec<u8>> {
        let typ = ResourceType::try_from(&rid.r#type[..])?;
        match typ {
            ResourceType::Policy => Ok(std::include_str!("policy.json").as_bytes().to_vec()),
            ResourceType::SigstoreConfig => Ok(std::include_str!("sigstore_config.yaml")
                .as_bytes()
                .to_vec()),
            ResourceType::GPGPublicKey => Ok(std::include_str!("pubkey.gpg").as_bytes().to_vec()),
            ResourceType::CosignVerificationKey => {
                Ok(std::include_str!("cosign.pub").as_bytes().to_vec())
            }
            ResourceType::Credential => Ok(std::include_str!("auth.json").as_bytes().to_vec()),
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
