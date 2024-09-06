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

use crate::resource::ResourceProvider;

/// Image security config dir contains important information such as
/// security policy configuration file and signature verification configuration file.
pub const IMAGE_SECURITY_CONFIG_SUBDIR: &str = "image-security";

pub struct SignatureValidator {
    policy: Policy,

    resource_provider: Arc<ResourceProvider>,

    #[cfg(feature = "signature-simple")]
    simple_signing_sigstore_config: Option<policy::SigstoreConfig>,
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
            PolicyReqType::Reject => bail!(
                "Policy `reject` rejects image {}",
                image.reference.to_string()
            ),
            PolicyReqType::SimpleSigning(inner) => {
                self.simple_signing_allows_image(inner, image, auth).await
            }
            PolicyReqType::Cosign(inner) => self.cosign_allows_image(inner, image, auth).await,
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
    ) -> Result<()> {
        let reference = oci_client::Reference::try_from(image_reference)?;
        let mut image = Image::default_with_reference(reference);
        image.set_manifest_digest(image_digest)?;

        // Get the policy set that matches the image.
        let reqs = self.policy.requirements_for_image(&image);
        if reqs.is_empty() {
            bail!("List of verification policy requirements must not be empty");
        }

        // The image must meet the requirements of each policy in the policy set.
        for req in reqs.iter() {
            self.check_image_requirement(req, &image, auth).await?;
        }

        Ok(())
    }

    pub(crate) async fn new(
        policy: &[u8],
        _simple_signing_sigstore_config: Option<Vec<u8>>,
        workdir: &Path,
        resource_provider: Arc<ResourceProvider>,
    ) -> Result<Self> {
        let policy: Policy = serde_json::from_slice(policy).context("parse image policy")?;
        tokio::fs::create_dir_all(workdir.join(IMAGE_SECURITY_CONFIG_SUBDIR)).await?;

        #[cfg(feature = "signature-simple")]
        let simple_signing_sigstore_config = match _simple_signing_sigstore_config {
            Some(cfg) => {
                let sig_store_config_dir = workdir.join(policy::simple::SIG_STORE_CONFIG_SUB_DIR);
                tokio::fs::create_dir_all(&sig_store_config_dir)
                    .await
                    .context("Create Simple Signing sigstore-config dir failed")?;
                let mut sigstore_config: policy::SigstoreConfig =
                    serde_yaml::from_slice(&cfg).context("parse simple signing sigstore config")?;
                sigstore_config
                    .update_from_path(&sig_store_config_dir)
                    .await?;
                Some(sigstore_config)
            }
            None => None,
        };

        Ok(Self {
            policy,
            resource_provider,

            #[cfg(feature = "signature-simple")]
            simple_signing_sigstore_config,
        })
    }
}
