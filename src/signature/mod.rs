// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod image;
pub mod mechanism;
pub mod payload;
pub mod policy;

#[cfg(feature = "getresource")]
pub use getresource::allows_image;

#[cfg(not(feature = "getresource"))]
pub use no_getresource::allows_image;

#[cfg(feature = "getresource")]
pub mod getresource {
    use crate::{config::Paths, signature::policy::Policy};

    use super::image::Image;

    use std::convert::TryFrom;

    use anyhow::Result;
    use oci_distribution::secrets::RegistryAuth;

    /// `allows_image` will check all the `PolicyRequirements` suitable for
    /// the given image. The `PolicyRequirements` is defined in
    /// [`policy_path`] and may include signature verification.
    #[cfg(feature = "signature")]
    pub async fn allows_image(
        image_reference: &str,
        image_digest: &str,
        auth: &RegistryAuth,
        file_paths: &Paths,
    ) -> Result<()> {
        use crate::resource;

        let reference = oci_distribution::Reference::try_from(image_reference)?;
        let mut image = Image::default_with_reference(reference);
        image.set_manifest_digest(image_digest)?;

        // Read the set of signature schemes that need to be verified
        // of the image from the policy configuration.
        let policy_json_string = resource::get_resource(&file_paths.policy_path).await?;
        let mut policy = serde_json::from_slice::<Policy>(&policy_json_string)?;
        let schemes = policy.signature_schemes(&image);

        // Get the necessary resources from KBS if needed.
        for scheme in schemes {
            scheme.init(file_paths).await?;
        }

        policy
            .is_image_allowed(image, auth)
            .await
            .map_err(|e| anyhow::anyhow!("Validate image failed: {:?}", e))
    }
}
