// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[allow(unused_imports)]
#[macro_use]
extern crate strum;

use crate::kbc_modules::{KbcCheckInfo, KbcInstance, KbcModuleList};
use anyhow::*;
use async_trait::async_trait;
use std::collections::HashMap;

mod common;
mod kbc_modules;

/// Attestation Agent (AA for short) is a rust library crate for attestation procedure
/// in confidential containers. It provides kinds of service APIs that need to make
/// requests to the Relying Party (Key Broker Service) in Confidential Containers,
/// and establishes an attestation and connection between the corresponding Key Broker
/// Client (KBC) and KBS, so as to obtain the trusted services or resources of KBS.
///
/// # Example
///
/// ```rust
/// use attestation_agent::AttestationAgent;
/// use attestation_agent::AttestationAPIs;
///
/// let mut aa = AttestationAgent::new();
///
/// let key_result = aa.decrypt_image_layer_annotation(
///     "sample_kbc".to_string(),
///     "https://xxxxx".to_string(),
///     "example_annotation".to_string()
/// );
/// ```

/// `AttestationAPIs` defines the service APIs of attestation agent that need to make requests
///  to the Relying Party (Key Broker Service) in Confidential Containers.
///
/// For every service API, the `kbc_name` and `kbs_uri` is necessary, `kbc_name` tells
/// attestation agent which KBC module it should use and `kbs_uri` specifies the KBS address.
#[async_trait]
pub trait AttestationAPIs {
    /// `decrypt_image_layer_annotation`is used to decrypt the encrypted information in `annotation`.
    /// The specific format of `annotation` is defined by different KBC and corresponding KBS.
    /// The decryption method may be to obtain the key from KBS for decryption, or
    /// directly send the `annotation` to KBS for decryption, which depends on the
    /// specific implementation of each KBC module.
    async fn decrypt_image_layer_annotation(
        &mut self,
        kbc_name: String,
        kbs_uri: String,
        annotation: String,
    ) -> Result<Vec<u8>>;

    /// `download_confidential_resource` is used to request KBS to obtain confidential resources, including
    /// confidential data or files. The specific format of `resource_description` is defined by
    /// different KBC and corresponding KBS.
    async fn download_confidential_resource(
        &mut self,
        kbc_name: String,
        kbs_uri: String,
        resource_description: String,
    ) -> Result<Vec<u8>>;
}

pub struct AttestationAgent {
    kbc_module_list: KbcModuleList,
    kbc_instance_map: HashMap<String, KbcInstance>,
}

impl Default for AttestationAgent {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationAgent {
    pub fn new() -> Self {
        let kbc_module_list = KbcModuleList::new();
        let kbc_instance_map = HashMap::new();
        AttestationAgent {
            kbc_module_list,
            kbc_instance_map,
        }
    }

    fn register_instance(&mut self, kbc_name: String, kbc_instance: KbcInstance) {
        self.kbc_instance_map.insert(kbc_name, kbc_instance);
    }

    fn instantiate_kbc(&mut self, kbc_name: String, kbs_uri: String) -> Result<()> {
        let instantiate_func = self.kbc_module_list.get_func(&kbc_name)?;
        let kbc_instance = (instantiate_func)(kbs_uri);
        self.register_instance(kbc_name, kbc_instance);
        Ok(())
    }

    #[allow(dead_code)]
    fn check(&self, kbc_name: String) -> Result<KbcCheckInfo> {
        let kbc_instance = self
            .kbc_instance_map
            .get(&kbc_name)
            .ok_or_else(|| anyhow!("The KBC instance does not existing!"))?;
        let check_info: KbcCheckInfo = kbc_instance.check()?;
        Ok(check_info)
    }
}

#[async_trait]
impl AttestationAPIs for AttestationAgent {
    async fn decrypt_image_layer_annotation(
        &mut self,
        kbc_name: String,
        kbs_uri: String,
        annotation: String,
    ) -> Result<Vec<u8>> {
        if self.kbc_instance_map.get_mut(&kbc_name).is_none() {
            self.instantiate_kbc(kbc_name.clone(), kbs_uri)?;
        }
        let kbc_instance = self
            .kbc_instance_map
            .get_mut(&kbc_name)
            .ok_or_else(|| anyhow!("The KBC instance does not existing!"))?;
        let plain_payload = kbc_instance.decrypt_payload(&annotation).await?;
        Ok(plain_payload)
    }

    async fn download_confidential_resource(
        &mut self,
        kbc_name: String,
        kbs_uri: String,
        resource_description: String,
    ) -> Result<Vec<u8>> {
        if self.kbc_instance_map.get_mut(&kbc_name).is_none() {
            self.instantiate_kbc(kbc_name.clone(), kbs_uri)?;
        }
        let kbc_instance = self
            .kbc_instance_map
            .get_mut(&kbc_name)
            .ok_or_else(|| anyhow!("The KBC instance does not existing!"))?;
        let resource = kbc_instance.get_resource(resource_description).await?;
        Ok(resource)
    }
}
