// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[allow(unused_imports)]
#[macro_use]
extern crate strum;

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use attester::{detect_tee_type, BoxedAttester};
use kbc::{AnnotationPacket, KbcCheckInfo, KbcInstance, KbcModuleList};
use resource_uri::ResourceUri;
use std::{collections::HashMap, path::Path};

mod config;

#[cfg(any(feature = "cc_kbc", feature = "kbs_as"))]
use token::GetToken;

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
/// let mut aa = AttestationAgent::new(None);
///
/// let key_result = aa.decrypt_image_layer_annotation(
///     "sample_kbc",
///     "https://xxxxx",
///     "example_annotation"
/// );
/// ```

/// `AttestationAPIs` defines the service APIs of attestation agent that need to make requests
///  to the Relying Party (Key Broker Service) in Confidential Containers.
///
/// For every service API, the `kbc_name` and `kbs_uri` is necessary, `kbc_name` tells
/// attestation agent which KBC module it should use and `kbs_uri` specifies the KBS address.
#[async_trait]
pub trait AttestationAPIs {
    /// Decrypt the encrypted information in `annotation`.
    ///
    /// The specific format of `annotation` is defined by different KBC and corresponding KBS.
    /// The decryption method may be to obtain the key from KBS for decryption, or
    /// directly send the `annotation` to KBS for decryption, which depends on the
    /// specific implementation of each KBC module.
    ///
    /// TODO: move this API to Confidential Data Hub
    async fn decrypt_image_layer_annotation(
        &mut self,
        kbc_name: &str,
        kbs_uri: &str,
        annotation: &str,
    ) -> Result<Vec<u8>>;

    /// Request KBS to obtain confidential resources, including confidential data or files.
    ///
    /// `resource_uri` is a KBS Resource URI pointing to a specific resource.
    ///
    /// TODO: remove this API
    async fn download_confidential_resource(
        &mut self,
        kbc_name: &str,
        resource_path: &str,
        kbs_uri: &str,
    ) -> Result<Vec<u8>>;

    /// Get attestation Token
    async fn get_token(&mut self, token_type: &str) -> Result<Vec<u8>>;

    /// Get TEE hardware signed evidence that includes the runtime data.
    async fn get_evidence(&mut self, runtime_data: &[u8]) -> Result<Vec<u8>>;

    /// Extend runtime measurement register
    async fn extend_runtime_measurement(
        &mut self,
        events: Vec<Vec<u8>>,
        register_index: Option<u64>,
    ) -> Result<()>;
}

#[allow(dead_code)]
/// Attestation agent to provide attestation service.
pub struct AttestationAgent<'a> {
    config_file_path: &'a Path,
    kbc_module_list: KbcModuleList,
    kbc_instance_map: HashMap<String, KbcInstance>,
}

impl<'a> Default for AttestationAgent<'a> {
    fn default() -> Self {
        Self::new(None)
    }
}

impl<'a> AttestationAgent<'a> {
    /// Create a new instance of [AttestationAgent].
    pub fn new(config_path: Option<&'a str>) -> Self {
        let config_path = config_path.unwrap_or(config::DEFAULT_AA_CONFIG_PATH);
        AttestationAgent {
            config_file_path: &Path::new(config_path),
            kbc_module_list: KbcModuleList::new(),
            kbc_instance_map: HashMap::new(),
        }
    }

    pub fn about(&self) -> String {
        let kbc_names_list = self.kbc_module_list.names().join(", ");
        format!("KBCs: {kbc_names_list}")
    }

    fn register_instance(&mut self, kbc_name: String, kbc_instance: KbcInstance) {
        self.kbc_instance_map.insert(kbc_name, kbc_instance);
    }

    fn instantiate_kbc(&mut self, kbc_name: &str, kbs_uri: &str) -> Result<()> {
        let instantiate_func = self.kbc_module_list.get_func(kbc_name)?;
        let kbc_instance = (instantiate_func)(kbs_uri.to_string());
        self.register_instance(kbc_name.to_string(), kbc_instance);
        Ok(())
    }

    #[allow(dead_code)]
    fn check(&self, kbc_name: String) -> Result<KbcCheckInfo> {
        self.kbc_instance_map
            .get(&kbc_name)
            .ok_or_else(|| anyhow!("The KBC instance does not exist!"))?
            .check()
    }
}

#[async_trait]
impl<'a> AttestationAPIs for AttestationAgent<'a> {
    async fn decrypt_image_layer_annotation(
        &mut self,
        kbc_name: &str,
        kbs_uri: &str,
        annotation: &str,
    ) -> Result<Vec<u8>> {
        if !self.kbc_instance_map.contains_key(kbc_name) {
            self.instantiate_kbc(kbc_name, kbs_uri)?;
        }

        let annotation: AnnotationPacket = serde_json::from_str(annotation)?;

        self.kbc_instance_map
            .get_mut(kbc_name)
            .ok_or_else(|| anyhow!("The KBC instance does not existing!"))?
            .decrypt_payload(annotation)
            .await
    }

    async fn download_confidential_resource(
        &mut self,
        kbc_name: &str,
        resource_path: &str,
        kbs_uri: &str,
    ) -> Result<Vec<u8>> {
        let resource_uri = ResourceUri::new(kbs_uri, resource_path)?;

        if !self.kbc_instance_map.contains_key(kbc_name) {
            self.instantiate_kbc(kbc_name, kbs_uri)?;
        }

        self.kbc_instance_map
            .get_mut(kbc_name)
            .ok_or_else(|| anyhow!("The KBC instance does not existing!"))?
            .get_resource(resource_uri)
            .await
    }

    #[allow(unused_variables)]
    #[allow(unreachable_code)]
    async fn get_token(&mut self, _token_type: &str) -> Result<Vec<u8>> {
        let token = match _token_type {
            #[cfg(any(feature = "cc_kbc", feature = "kbs_as"))]
            "kbs" => {
                let kbs_host_url = config::get_host_url().await?;
                let kbs_token = token::kbs::KbsTokenGetter::default()
                    .get_token(kbs_host_url)
                    .await?;
                kbs_token
            }
            typ => bail!("Unsupported token type {typ}"),
        };

        Ok(token)
    }

    /// Get TEE hardware signed evidence that includes the runtime data.
    async fn get_evidence(&mut self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        let tee_type = detect_tee_type();
        let attester = TryInto::<BoxedAttester>::try_into(tee_type)?;
        let evidence = attester.get_evidence(runtime_data.to_vec()).await?;
        Ok(evidence.into_bytes())
    }

    /// Extend runtime measurement register
    async fn extend_runtime_measurement(
        &mut self,
        events: Vec<Vec<u8>>,
        register_index: Option<u64>,
    ) -> Result<()> {
        let tee_type = detect_tee_type();
        let attester = TryInto::<BoxedAttester>::try_into(tee_type)?;
        attester
            .extend_runtime_measurement(events, register_index)
            .await?;
        Ok(())
    }
}
