// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::image;
use crate::policy;
use anyhow::*;
use std::fs;

mod sigstore;
mod verify;

pub use sigstore::SigstoreConfig;
pub use sigstore::SIGSTORE_CONFIG_DIR;
pub use sigstore::{format_sigstore_name, get_sigs_from_specific_sigstore};
pub use verify::verify_sig_and_extract_payload;

#[derive(EnumString, Display, Debug, PartialEq)]
pub enum KeyType {
    #[strum(to_string = "GPGKeys")]
    Gpg,
}

#[allow(unused_assignments)]
pub fn judge_signatures_accept(
    signedby_req: &policy::PolicyReqSignedBy,
    image: &mut image::Image,
) -> Result<()> {
    // FIXME: only support "GPGKeys" type now.
    //
    // refer to https://github.com/confidential-containers/image-rs/issues/14
    if signedby_req.key_type != KeyType::Gpg.to_string() {
        return Err(anyhow!(
            "Unknown key type in policy config: only support {} now.",
            KeyType::Gpg.to_string()
        ));
    }

    if !signedby_req.key_path.is_empty() && !signedby_req.key_data.is_empty() {
        return Err(anyhow!("Both keyPath and keyData specified."));
    }

    let pubkey_ring = if !signedby_req.key_data.is_empty() {
        base64::decode(&signedby_req.key_data)?
    } else {
        fs::read(&signedby_req.key_path).map_err(|e| {
            anyhow!(
                "Read SignedBy keyPath failed: {:?}, path: {}",
                e,
                &signedby_req.key_path
            )
        })?
    };

    let sigs = image.signatures(&signedby_req.scheme)?;
    let mut reject_reasons: Vec<anyhow::Error> = Vec::new();

    for sig in sigs.iter() {
        match judge_single_signature(
            image,
            signedby_req.signed_identity.as_ref(),
            pubkey_ring.clone(),
            sig.to_vec(),
        ) {
            // One accepted signature is enough.
            Result::Ok(()) => {
                return Ok(());
            }
            Result::Err(e) => {
                reject_reasons.push(e);
            }
        }
    }

    if reject_reasons.is_empty() {
        reject_reasons.push(anyhow!("Can not find any signatures."));
    }

    Err(anyhow!(format!(
        "The signatures do not satisfied! Reject reason: {:?}",
        reject_reasons
    )))
}

pub fn judge_single_signature(
    image: &image::Image,
    signed_identity: Option<&Box<dyn policy::PolicyReferenceMatcher>>,
    pubkey_ring: Vec<u8>,
    sig: Vec<u8>,
) -> Result<()> {
    // Verify the signature with the pubkey ring.
    let sig_payload = verify::verify_sig_and_extract_payload(pubkey_ring, sig)?;

    // Verify whether the information recorded in signature payload
    // is consistent with the real information of the image.
    //
    // The match policy of image-reference is the "signedIdentity" field.
    sig_payload.validate_signed_docker_reference(&image.reference, signed_identity)?;
    sig_payload.validate_signed_docker_manifest_digest(&image.manifest_digest.to_string())?;

    Ok(())
}

#[allow(unused_assignments)]
pub fn get_signatures(image: &mut image::Image) -> Result<Vec<Vec<u8>>> {
    // Get image digest (manifest digest)
    let image_digest = if !image.manifest_digest.is_empty() {
        image.manifest_digest.clone()
    } else if let Some(d) = image.reference.digest() {
        image::digest::Digest::try_from(d)?
    } else {
        return Err(anyhow!("Missing image digest"));
    };

    // Format the sigstore name: `image-repository@digest-algorithm=digest-value`.
    let sigstore_name = sigstore::format_sigstore_name(&image.reference, image_digest);

    // If the registry support `X-Registry-Supports-Signatures` API extension,
    // try to get signatures from the registry first.
    // Else, get signatures from "sigstore" according to the sigstore config file.
    // (https://github.com/containers/image/issues/384)
    //
    // TODO: Add get signatures from registry X-R-S-S API extension.
    //
    // issue: https://github.com/confidential-containers/image-rs/issues/12
    let sigstore_config =
        sigstore::SigstoreConfig::new_from_configs(sigstore::SIGSTORE_CONFIG_DIR)?;

    let sigstore_base_url = sigstore_config
        .base_url(&image.reference)?
        .ok_or_else(|| anyhow!("The sigstore base url is none"))?;

    let sigstore = format!("{}/{}", &sigstore_base_url, &sigstore_name);
    let sigstore_uri =
        url::Url::parse(&sigstore).map_err(|e| anyhow!("Failed to parse sigstore_uri: {:?}", e))?;

    let sigs = sigstore::get_sigs_from_specific_sigstore(sigstore_uri)?;

    Ok(sigs)
}
