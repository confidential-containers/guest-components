// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(feature = "signature")]
use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::Result;
use oci_distribution::secrets::RegistryAuth;
use tokio::sync::Mutex;

use crate::secure_channel::SecureChannel;

#[cfg(feature = "signature")]
pub mod image;
#[cfg(feature = "signature")]
pub mod mechanism;
#[cfg(feature = "signature")]
pub mod payload;
#[cfg(feature = "signature")]
pub mod policy;

/// Default policy file path.
pub const POLICY_FILE_PATH: &str = "/run/image-security/security_policy.json";

#[cfg(feature = "signature")]
/// `allows_image` will check all the `PolicyRequirements` suitable for
/// the given image. The `PolicyRequirements` is defined in
/// [`POLICY_FILE_PATH`] and may include signature verification.
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
    let mut image = self::image::Image::default_with_reference(reference);
    image.set_manifest_digest(image_digest)?;

    // Read the set of signature schemes that need to be verified
    // of the image from the policy configuration.
    let policy = self::policy::Policy::from_file(POLICY_FILE_PATH).await?;
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

#[cfg(not(feature = "signature"))]
pub async fn allows_image(
    _image_reference: &str,
    _image_digest: &str,
    _secure_channel: Arc<Mutex<SecureChannel>>,
    _auth: &RegistryAuth,
) -> Result<()> {
    Ok(())
}
