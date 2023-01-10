// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Secure-Channel is a module used to connect KBS (Relying Party)
//! for confidential resources

use attestation_agent::AttestationAPIs;
use attestation_agent::AttestationAgent;
use ocicrypt_rs::config::{OcicryptConfig, OCICRYPT_ENVVARNAME};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::result::Result::Ok;
use thiserror::Error;
use tokio::fs;
use tonic::transport::Channel;

use self::get_resource::{
    get_resource_service_client::GetResourceServiceClient, GetResourceRequest,
};

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

pub type Result<T> = std::result::Result<T, SecureChannelError>;

#[derive(Error, Debug)]
pub enum SecureChannelError {
    #[error("KBC parameters missing name: {0}")]
    KBCParamsMissingName(String),

    #[error("KBC parameters missing URI: {0}")]
    KBCParamsMissingURI(String),

    #[error("KBC parameters specifies unknown KBC/KBS pair: {0}")]
    KBCParamsUnknownKBPair(String),

    #[error("Failed to get description for resource {0}: {1}")]
    ResourceDescriptionFail(String, serde_json::Error),

    #[error("Write resource {0} to {1} failed: {2}")]
    WriteResourceError(String, String, std::io::Error),

    #[error("gRPC connect failed: {0}")]
    GRPCConnectFail(tonic::transport::Error),

    #[error("gRPC resource service failed: {0}")]
    GRPCServiceFail(tonic::Status),

    #[error("Native AA resource service failed: {0}")]
    NativeAAServiceFail(anyhow::Error),
}

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

/// SecureChannel to connect with KBS
pub struct SecureChannel {
    /// Get Resource Service client.
    client: Client,
    kbc_name: String,
    kbs_uri: String,
}

/// Types of the Client underlying a SecureChannel
enum Client {
    /// Get Resource Service gRPC client
    ServiceGRPC(GetResourceServiceClient<Channel>),
    /// Get Rserouce native AA client
    NativeAA(AttestationAgent),
}

impl Client {
    /// Retrieves confidential resource
    async fn get_resource(
        &mut self,
        kbc_name: &str,
        kbs_uri: &str,
        resource_description: String,
    ) -> Result<Vec<u8>> {
        match self {
            Self::ServiceGRPC(client) => {
                let req = tonic::Request::new(GetResourceRequest {
                    kbc_name: kbc_name.to_string(),
                    kbs_uri: kbs_uri.to_string(),
                    resource_description,
                });
                Ok(client
                    .get_resource(req)
                    .await
                    .map_err(|e| SecureChannelError::GRPCServiceFail(e))?
                    .into_inner()
                    .resource)
            }
            Self::NativeAA(aa) => aa
                .download_confidential_resource(kbc_name, kbs_uri, &resource_description)
                .await
                .map_err(|e| SecureChannelError::NativeAAServiceFail(e)),
        }
    }
}

impl SecureChannel {
    /// Create a new [`SecureChannel`], the input parameter:
    /// * `aa_kbc_params`: s string with format `<kbc_name>::<kbs_uri>`.
    pub async fn new(aa_kbc_params: &str) -> Result<Self> {
        // unzip here is unstable
        if let Some((kbc_name, kbs_uri)) = aa_kbc_params.split_once("::") {
            if kbc_name.is_empty() {
                return Err(SecureChannelError::KBCParamsMissingName(
                    aa_kbc_params.into(),
                ));
            }

            if kbs_uri.is_empty() {
                return Err(SecureChannelError::KBCParamsMissingURI(
                    aa_kbc_params.into(),
                ));
            }

            Ok(Self {
                client: if is_native_aa() {
                    Client::NativeAA(AttestationAgent::new())
                } else {
                    Client::ServiceGRPC(
                        GetResourceServiceClient::connect(AA_GETRESOURCE_ADDR)
                            .await
                            .map_err(|e| SecureChannelError::GRPCConnectFail(e))?,
                    )
                },
                kbc_name: kbc_name.into(),
                kbs_uri: kbs_uri.into(),
            })
        } else {
            Err(SecureChannelError::KBCParamsUnknownKBPair(
                aa_kbc_params.into(),
            ))
        }
    }

    /// Get resource from using, using `resource_name` as `name` in a ResourceDescription.
    /// Please refer to https://github.com/confidential-containers/image-rs/blob/main/docs/ccv1_image_security_design.md#get-resource-service
    /// for more information.
    /// Then save the gathered data into `path`
    pub async fn get_resource(
        &mut self,
        resource_name: &str,
        optional: HashMap<String, String>,
        path: &str,
    ) -> Result<()> {
        let resource_description =
            serde_json::to_string(&ResourceDescription::new(resource_name, optional)).map_err(
                |e| SecureChannelError::ResourceDescriptionFail(resource_name.into(), e),
            )?;

        let res = self
            .client
            .get_resource(&self.kbc_name, &self.kbs_uri, resource_description)
            .await?;

        fs::write(path, res).await.map_err(|e| {
            SecureChannelError::WriteResourceError(resource_name.into(), path.into(), e)
        })?;

        Ok(())
    }
}

fn is_native_aa() -> bool {
    let ocicrypt_config = match OcicryptConfig::from_env(OCICRYPT_ENVVARNAME) {
        Ok(oc) => oc,
        Err(_) => return false,
    };
    if let Some(ocicrypt_config) = ocicrypt_config {
        let key_providers = ocicrypt_config.key_providers;
        for (provider_name, attrs) in key_providers.iter() {
            if provider_name == NATIVE_AA_NAME && attrs.native.is_some() {
                return true;
            }
        }
    }
    false
}
