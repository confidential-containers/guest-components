// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{collections::HashMap, path::Path};

use anyhow::*;
use attestation_agent::AttestationAPIs;
use attestation_agent::AttestationAgent;
use oci_distribution::Reference;
use ocicrypt_rs::config::{OcicryptConfig, OCICRYPT_ENVVARNAME};
use serde::{Deserialize, Serialize};
use std::result::Result::Ok;
use tokio::fs;
use tonic::transport::Channel;

use crate::{image::Image, policy::Policy};

use self::get_resource::{
    get_resource_service_client::GetResourceServiceClient, GetResourceRequest,
};

mod get_resource {
    #![allow(unknown_lints)]
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("getresource");
}

/// Image security config dir contains important information such as
/// security policy configuration file and signature verification configuration file.
/// Therefore, it is necessary to ensure that the directory is stored in a safe place.
///
/// The reason for using the `/run` directory here is that in general HW-TEE,
/// the `/run` directory is mounted in `tmpfs`, which is located in the encrypted memory protected by HW-TEE.
pub const IMAGE_SECURITY_CONFIG_DIR: &str = "/run/image-security";
pub const POLICY_FILE_PATH: &str = "/run/image-security/security_policy.json";

/// Attestation Agent's GetResource gRPC address.
/// It's given <https://github.com/confidential-containers/attestation-agent#run>
pub const AA_GETRESOURCE_ADDR: &str = "http://127.0.0.1:50001";
/// The native attestation agent's name.
/// It's given <https://github.com/confidential-containers/attestation-agent>
pub const NATIVE_AA_NAME: &str = "attestation-agent";

/// Signature submodule agent for image signature verification.
pub struct Agent {
    /// Get Resource Client
    client: SigClient,
    kbc_name: String,
    kbs_uri: String,
}

// Types of the signature client
enum SigClient {
    /// Get Resource Service gRPC client
    ServiceGPRC(GetResourceServiceClient<Channel>),
    /// Get Rserouce native AA client
    NativeAA(AttestationAgent),
}

impl SigClient {
    // get_resource retrieves verification resource
    async fn get_resource(
        &mut self,
        kbc_name: String,
        kbs_uri: String,
        resource_description: String,
    ) -> Result<Vec<u8>> {
        match self {
            Self::ServiceGPRC(client) => {
                let req = tonic::Request::new(GetResourceRequest {
                    kbc_name,
                    kbs_uri,
                    resource_description,
                });
                Ok(client.get_resource(req).await?.into_inner().resource)
            }
            Self::NativeAA(aa) => {
                aa.download_confidential_resource(kbc_name, kbs_uri, resource_description)
                    .await
            }
        }
    }
}

/// The resource description that will be passed to AA when get resource.
#[derive(Serialize, Deserialize, Debug)]
struct ResourceDescription {
    name: String,
    optional: HashMap<String, String>,
}

impl ResourceDescription {
    /// Create a new ResourceDescription with resource name.
    pub fn new(name: &str) -> Self {
        ResourceDescription {
            name: name.to_string(),
            optional: HashMap::new(),
        }
    }
}

impl Agent {
    /// Create a new signature-agent, the input parameter:
    /// * `aa_kbc_params`: s string with format `<kbc_name>::<kbs_uri>`.
    pub async fn new(aa_kbc_params: &str) -> Result<Self> {
        // unzip here is unstable
        if let Some((kbc_name, kbs_uri)) = aa_kbc_params.split_once("::") {
            if kbc_name.is_empty() {
                return Err(anyhow!("aa_kbc_params: missing KBC name"));
            }
            if kbs_uri.is_empty() {
                return Err(anyhow!("aa_kbc_params: missing KBS URI"));
            }
            Ok(Self {
                client: if is_native_aa() {
                    SigClient::NativeAA(AttestationAgent::new())
                } else {
                    SigClient::ServiceGPRC(
                        GetResourceServiceClient::connect(AA_GETRESOURCE_ADDR).await?,
                    )
                },
                kbs_uri: kbs_uri.into(),
                kbc_name: kbc_name.into(),
            })
        } else {
            Err(anyhow!("aa_kbc_params: KBC/KBS pair not found"))
        }
    }

    /// Get resource from using, using `resource_name` as `name` in a ResourceDescription.
    /// Please refer to https://github.com/confidential-containers/image-rs/blob/main/docs/ccv1_image_security_design.md#get-resource-service
    /// for more information.
    /// Then save the gathered data into `path`
    async fn get_resource(&mut self, resource_name: &str, path: &str) -> Result<()> {
        let resource_description = serde_json::to_string(&ResourceDescription::new(resource_name))?;
        let res = self
            .client
            .get_resource(
                self.kbc_name.clone(),
                self.kbs_uri.clone(),
                resource_description,
            )
            .await?;
        fs::write(path, res).await?;
        Ok(())
    }

    /// `check_policy` judges whether the container image is allowed to be pulled and run.
    ///
    /// According to the configuration of the policy file. The policy may include
    /// signatures, if a signature of the container image needs to be verified, the
    /// specified signature scheme is used for signature verification.
    pub async fn allows_image(&mut self, image_reference: &str, image_digest: &str) -> Result<()> {
        if !Path::new(IMAGE_SECURITY_CONFIG_DIR).exists() {
            fs::create_dir_all(IMAGE_SECURITY_CONFIG_DIR)
                .await
                .map_err(|e| anyhow!("Create image security runtime config dir failed: {:?}", e))?;
        }

        // if Policy config file does not exist, get if from KBS.
        if !Path::new(POLICY_FILE_PATH).exists() {
            self.get_resource("Policy", POLICY_FILE_PATH).await?;
        }

        let policy = Policy::from_file(POLICY_FILE_PATH).await?;

        let reference = Reference::try_from(image_reference)?;
        let mut image = Image::default_with_reference(reference);
        image.set_manifest_digest(image_digest)?;

        // Read the set of signature schemes that need to be verified
        // of the image from the policy configuration.
        let schemes = policy.signature_schemes(&image);

        // Get the necessary resources from KBS if needed.
        for scheme in schemes {
            scheme.init().await?;
            let resource_manifest = scheme.resource_manifest();
            for (resource_name, path) in resource_manifest {
                self.get_resource(resource_name, path).await?;
            }
        }

        policy
            .is_image_allowed(image)
            .await
            .map_err(|e| anyhow!("Validate image failed: {:?}", e))
    }
}

fn is_native_aa() -> bool {
    let ocicrypt_config = match OcicryptConfig::from_env(OCICRYPT_ENVVARNAME) {
        Ok(oc) => oc,
        Err(_) => return false,
    };
    let key_providers = ocicrypt_config.key_providers;
    for (provider_name, attrs) in key_providers.iter() {
        if provider_name == NATIVE_AA_NAME && attrs.native.is_some() {
            return true;
        }
    }
    false
}
