// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod image;
pub mod mechanism;
pub mod payload;
pub mod policy;

use std::{collections::HashMap, convert::TryFrom, path::Path, sync::Arc};

use anyhow::*;
use oci_distribution::{secrets::RegistryAuth, Reference};
use tokio::sync::Mutex;

use crate::secure_channel::SecureChannel;

use self::{image::Image, policy::Policy};

pub const POLICY_FILE_PATH: &str = "/run/image-security/security_policy.json";

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
    if !Path::new(POLICY_FILE_PATH).exists() {
        secure_channel
            .lock()
            .await
            .get_resource("Policy", HashMap::new(), POLICY_FILE_PATH)
            .await?;
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
            secure_channel
                .lock()
                .await
                .get_resource(resource_name, HashMap::new(), path)
                .await?;
        }
    }

    policy
        .is_image_allowed(image, auth)
        .await
        .map_err(|e| anyhow!("Validate image failed: {:?}", e))
}
