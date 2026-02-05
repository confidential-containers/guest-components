// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod image;
pub mod payload;
pub mod policy;

use std::{path::Path, sync::Arc};

use image::Image;
use policy::policy_requirement::PolicyReqType;
pub use policy::Policy;

use anyhow::{bail, Context, Result};
use oci_client::secrets::RegistryAuth;
use thiserror::Error;

use crate::{config::ProxyConfig, resource::ResourceProvider};

/// Image security config dir contains important information such as
/// security policy configuration file and signature verification configuration file.
pub const IMAGE_SECURITY_CONFIG_SUBDIR: &str = "image-security";

pub type SignatureResult<T> = std::result::Result<T, SignatureError>;

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Failed to parse image reference: {0}")]
    IllegalImageReference(String),

    #[error("Illegal image digest: {0}")]
    IllegalImageDigest(String),

    #[error("Denied by policy: {source}")]
    DeniedByPolicy {
        #[source]
        source: anyhow::Error,
    },

    #[error("Invalid image policy file")]
    InvalidPolicyFile,

    #[error("Failed to initialize work dir")]
    InitializeWorkDir,

    #[cfg(feature = "signature-simple")]
    #[error("Invalid simple signing sigstore config")]
    InvalidSimpleSigningSigstoreConfig,

    #[cfg(feature = "signature-simple")]
    #[error("Failed to update sigstore config")]
    SigstoreConfigUpdateFailed {
        #[source]
        source: anyhow::Error,
    },
}

pub struct SignatureValidator {
    policy: Policy,

    resource_provider: Arc<ResourceProvider>,

    proxy_config: Option<ProxyConfig>,

    #[cfg(feature = "signature-simple")]
    simple_signing_sigstore_config: Option<policy::SigstoreConfig>,

    #[cfg(feature = "signature-cosign")]
    certificates: Vec<sigstore::registry::Certificate>,
}

impl SignatureValidator {
    #[cfg(not(feature = "signature-simple"))]
    async fn simple_signing_allows_image(
        &self,
        _parameters: &crate::signature::policy::SimpleParameters,
        _image: &Image,
        _auth: &RegistryAuth,
    ) -> Result<()> {
        bail!("feature \"signature-simple\" not enabled.")
    }

    #[cfg(not(feature = "signature-cosign"))]
    async fn cosign_allows_image(
        &self,
        _parameter: &crate::signature::policy::CosignParameters,
        _image: &Image,
        _auth: &RegistryAuth,
    ) -> Result<()> {
        bail!("feature \"signature-cosign\" not enabled.")
    }

    async fn check_image_requirement(
        &self,
        req: &PolicyReqType,
        image: &Image,
        auth: &RegistryAuth,
    ) -> Result<()> {
        match req {
            PolicyReqType::Accept => Ok(()),
            PolicyReqType::Reject => bail!("Policy `reject` rejects image {}", image.reference),
            PolicyReqType::SimpleSigning(inner) => self
                .simple_signing_allows_image(inner, image, auth)
                .await
                .context("rejected by `signedBy` rule"),
            PolicyReqType::Cosign(inner) => self
                .cosign_allows_image(inner, image, auth)
                .await
                .context("rejected by `sigstoreSigned` rule"),
        }
    }

    /// `check_image_signature` will check all the `PolicyRequirements` suitable for
    /// the given image. The `PolicyRequirements` is defined in [`policy::policy_requirement::PolicyReqType`]
    /// and may include signature verification.
    ///
    /// Returns Ok(()) if the requirement allows running an image.
    /// WARNING: This validates signatures and the manifest, but does not download or validate the
    /// layers. Users must validate that the layers match their expected digests.
    pub async fn check_image_signature(
        &self,
        image_reference: &str,
        image_digest: &str,
        auth: &RegistryAuth,
    ) -> SignatureResult<()> {
        let reference = oci_client::Reference::try_from(image_reference)
            .map_err(|_| SignatureError::IllegalImageReference(image_reference.to_string()))?;
        let mut image = Image::default_with_reference(reference);
        image
            .set_manifest_digest(image_digest)
            .map_err(|_| SignatureError::IllegalImageDigest(image_digest.to_string()))?;

        // Get the policy set that matches the image.
        let reqs = self.policy.requirements_for_image(&image);
        if reqs.is_empty() {
            // Note that if no policy covers the image, the image is considered to be allowed.
            return Ok(());
        }

        // The image must meet the requirements of each policy in the policy set.
        for req in reqs.iter() {
            self.check_image_requirement(req, &image, auth)
                .await
                .map_err(|source| SignatureError::DeniedByPolicy { source })?;
        }

        Ok(())
    }

    pub(crate) async fn new(
        policy: &[u8],
        _simple_signing_sigstore_config: Option<Vec<u8>>,
        workdir: &Path,
        proxy_config: Option<ProxyConfig>,
        certificates: Vec<String>,
        resource_provider: Arc<ResourceProvider>,
    ) -> SignatureResult<Self> {
        let policy: Policy =
            serde_json::from_slice(policy).map_err(|_| SignatureError::InvalidPolicyFile)?;
        tokio::fs::create_dir_all(workdir.join(IMAGE_SECURITY_CONFIG_SUBDIR))
            .await
            .map_err(|_| SignatureError::InitializeWorkDir)?;

        #[cfg(feature = "signature-simple")]
        let simple_signing_sigstore_config = match _simple_signing_sigstore_config {
            Some(cfg) => {
                let sig_store_config_dir = workdir.join(policy::simple::SIG_STORE_CONFIG_SUB_DIR);
                tokio::fs::create_dir_all(&sig_store_config_dir)
                    .await
                    .map_err(|_| SignatureError::InitializeWorkDir)?;
                let mut sigstore_config: policy::SigstoreConfig = serde_yaml::from_slice(&cfg)
                    .context("parse simple signing sigstore config")
                    .map_err(|_| SignatureError::InvalidSimpleSigningSigstoreConfig)?;
                sigstore_config
                    .update_from_path(&sig_store_config_dir)
                    .await
                    .map_err(|source| SignatureError::SigstoreConfigUpdateFailed { source })?;
                Some(sigstore_config)
            }
            None => None,
        };

        #[cfg(feature = "signature-cosign")]
        let certificates = certificates
            .into_iter()
            .map(|pem| pem.into_bytes())
            .map(|data| sigstore::registry::Certificate {
                encoding: sigstore::registry::CertificateEncoding::Pem,
                data,
            })
            .collect();

        Ok(Self {
            policy,
            resource_provider,
            proxy_config,
            #[cfg(feature = "signature-cosign")]
            certificates,
            #[cfg(feature = "signature-simple")]
            simple_signing_sigstore_config,
        })
    }
}
