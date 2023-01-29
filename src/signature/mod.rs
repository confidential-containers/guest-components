// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod image;
pub mod mechanism;
pub mod payload;
pub mod policy;

/// Default policy file path.
pub const POLICY_FILE_PATH: &str = "/run/image-security/security_policy.json";

#[cfg(feature = "getresource")]
pub use getresource::allows_image;

#[cfg(not(feature = "getresource"))]
pub use no_getresource::allows_image;

#[cfg(feature = "getresource")]
pub mod getresource {
    use crate::secure_channel::SecureChannel;
    use crate::signature::policy::Policy;

    use super::image::Image;
    use super::POLICY_FILE_PATH;

    use std::convert::TryFrom;
    use std::sync::Arc;

    use anyhow::Result;
    use oci_distribution::secrets::RegistryAuth;
    use tokio::sync::Mutex;

    /// `allows_image` will check all the `PolicyRequirements` suitable for
    /// the given image. The `PolicyRequirements` is defined in
    /// [`POLICY_FILE_PATH`] and may include signature verification.
    #[cfg(all(feature = "getresource", feature = "signature"))]
    pub async fn allows_image(
        image_reference: &str,
        image_digest: &str,
        secure_channel: Arc<Mutex<SecureChannel>>,
        auth: &RegistryAuth,
    ) -> Result<()> {
        // if Policy config file does not exist, get if from KBS.

        if !std::path::Path::new(POLICY_FILE_PATH).exists() {
            secure_channel
                .lock()
                .await
                .get_resource("Policy", std::collections::HashMap::new(), POLICY_FILE_PATH)
                .await?;
        }

        let reference = oci_distribution::Reference::try_from(image_reference)?;
        let mut image = Image::default_with_reference(reference);
        image.set_manifest_digest(image_digest)?;

        // Read the set of signature schemes that need to be verified
        // of the image from the policy configuration.
        let policy = Policy::from_file(POLICY_FILE_PATH).await?;
        let schemes = policy.signature_schemes(&image);

        // Get the necessary resources from KBS if needed.
        for scheme in schemes {
            scheme.init().await?;
            let resource_manifest = scheme.resource_manifest();
            for (resource_name, path) in resource_manifest {
                secure_channel
                    .lock()
                    .await
                    .get_resource(resource_name, std::collections::HashMap::new(), path)
                    .await?;
            }
        }

        policy
            .is_image_allowed(image, auth)
            .await
            .map_err(|e| anyhow::anyhow!("Validate image failed: {:?}", e))
    }
}

#[cfg(not(feature = "getresource"))]
pub mod no_getresource {
    use std::convert::TryFrom;

    use anyhow::Result;
    use log::warn;
    use oci_distribution::secrets::RegistryAuth;

    use crate::signature::{image::Image, policy::Policy, POLICY_FILE_PATH};

    pub async fn allows_image(
        image_reference: &str,
        image_digest: &str,
        auth: &RegistryAuth,
    ) -> Result<()> {
        // if Policy config file does not exist, get if from KBS.

        if !std::path::Path::new(POLICY_FILE_PATH).exists() {
            warn!("Non {POLICY_FILE_PATH} found, pass validation.");
            return Ok(());
        }

        let reference = oci_distribution::Reference::try_from(image_reference)?;
        let mut image = Image::default_with_reference(reference);
        image.set_manifest_digest(image_digest)?;

        // Read the set of signature schemes that need to be verified
        // of the image from the policy configuration.
        let policy = Policy::from_file(POLICY_FILE_PATH).await?;
        let schemes = policy.signature_schemes(&image);

        // Get the necessary resources from KBS if needed.
        for scheme in schemes {
            scheme.init().await?;
        }

        policy
            .is_image_allowed(image, auth)
            .await
            .map_err(|e| anyhow::anyhow!("Validate image failed: {:?}", e))
    }
}
