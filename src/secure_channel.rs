// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Fetch confidential resources from KBS (Relying Party).

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
#[cfg(feature = "keywrap-native")]
use attestation_agent::AttestationAPIs;
use serde::{Deserialize, Serialize};
use tokio::fs;

#[cfg(feature = "keywrap-grpc")]
use self::get_resource::{
    get_resource_service_client::GetResourceServiceClient, GetResourceRequest,
};

#[cfg(feature = "keywrap-grpc")]
mod get_resource {
    #![allow(unknown_lints)]
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("getresource");
}

/// Attestation Agent's GetResource gRPC address.
/// It's given <https://github.com/confidential-containers/attestation-agent#run>
pub const AA_GETRESOURCE_ADDR: &str = "http://127.0.0.1:50001";

/// The native attestation agent's name.
/// It's given <https://github.com/confidential-containers/attestation-agent>
pub const NATIVE_AA_NAME: &str = "attestation-agent";

/// The resource description that will be passed to AA when get resource.
#[derive(Serialize, Deserialize, Debug)]
struct ResourceDescription {
    name: String,
    optional: HashMap<String, String>,
}

impl ResourceDescription {
    /// Create a new ResourceDescription with resource name.
    pub fn new(name: &str, optional: HashMap<String, String>) -> Self {
        ResourceDescription {
            name: name.to_string(),
            optional,
        }
    }
}

/// Types of the Client underlying a SecureChannel
#[allow(dead_code)]
enum Client {
    /// Fake client which just return errors.
    None,
    #[cfg(feature = "keywrap-grpc")]
    /// Get Resource Service gRPC client
    ServiceGPRC(GetResourceServiceClient<tonic::transport::Channel>),
    #[cfg(feature = "keywrap-native")]
    /// Get Rserouce native AA client
    NativeAA(attestation_agent::AttestationAgent),
}

impl Client {
    /// Retrieves confidential resource
    async fn get_resource(
        &mut self,
        _kbc_name: &str,
        _kbs_uri: &str,
        _resource_description: String,
    ) -> Result<Vec<u8>> {
        match self {
            Self::None => Err(anyhow!("no mechanism to fetch resources")),
            #[cfg(feature = "keywrap-grpc")]
            Self::ServiceGPRC(client) => {
                let req = tonic::Request::new(GetResourceRequest {
                    kbc_name: _kbc_name.to_string(),
                    kbs_uri: _kbs_uri.to_string(),
                    resource_description: _resource_description,
                });
                Ok(client.get_resource(req).await?.into_inner().resource)
            }
            #[cfg(feature = "keywrap-native")]
            Self::NativeAA(aa) => {
                aa.download_confidential_resource(_kbc_name, _kbs_uri, &_resource_description)
                    .await
            }
        }
    }

    fn new_native_client() -> Option<Self> {
        #[cfg(feature = "keywrap-native")]
        {
            let ocicrypt_config = match ocicrypt_rs::config::OcicryptConfig::from_env(
                ocicrypt_rs::config::OCICRYPT_ENVVARNAME,
            ) {
                Ok(oc) => oc,
                Err(_) => return None,
            };
            if let Some(ocicrypt_config) = ocicrypt_config {
                let key_providers = ocicrypt_config.key_providers;
                for (provider_name, attrs) in key_providers.iter() {
                    if provider_name == NATIVE_AA_NAME && attrs.native.is_some() {
                        return Some(Client::NativeAA(attestation_agent::AttestationAgent::new()));
                    }
                }
            }
        }
        None
    }

    #[cfg(feature = "keywrap-grpc")]
    async fn new_grpc_client() -> Result<Self> {
        Ok(Client::ServiceGPRC(
            GetResourceServiceClient::connect(AA_GETRESOURCE_ADDR).await?,
        ))
    }
}

/// SecureChannel to connect with KBS
pub struct SecureChannel {
    /// Get Resource Service client.
    client: Client,
    kbc_name: String,
    kbs_uri: String,
}

impl SecureChannel {
    /// Create a new [`SecureChannel`], the input parameter:
    /// * `aa_kbc_params`: s string with format `<kbc_name>::<kbs_uri>`.
    pub async fn new(aa_kbc_params: &str) -> Result<Self> {
        // unzip here is unstable
        if let Some((kbc_name, kbs_uri)) = aa_kbc_params.split_once("::") {
            if kbc_name.is_empty() {
                bail!("aa_kbc_params: missing KBC name");
            }

            if kbs_uri.is_empty() {
                bail!("aa_kbc_params: missing KBS URI");
            }

            let client = match Client::new_native_client() {
                Some(v) => v,
                #[cfg(feature = "keywrap-grpc")]
                None => Client::new_grpc_client().await?,
                #[cfg(not(feature = "keywrap-grpc"))]
                None => Client::None,
            };

            Ok(Self {
                client,
                kbc_name: kbc_name.into(),
                kbs_uri: kbs_uri.into(),
            })
        } else {
            Err(anyhow!("aa_kbc_params: KBC/KBS pair not found"))
        }
    }

    /// Get resource from using, using `resource_name` as `name` in a ResourceDescription,
    /// then save the gathered data into `path`
    ///
    /// Please refer to https://github.com/confidential-containers/image-rs/blob/main/docs/ccv1_image_security_design.md#get-resource-service
    /// for more information.
    pub async fn get_resource(
        &mut self,
        resource_name: &str,
        optional: HashMap<String, String>,
        path: &str,
    ) -> Result<()> {
        let resource_description =
            serde_json::to_string(&ResourceDescription::new(resource_name, optional))?;
        let res = self
            .client
            .get_resource(&self.kbc_name, &self.kbs_uri, resource_description)
            .await?;
        fs::write(path, res).await?;
        Ok(())
    }
}
