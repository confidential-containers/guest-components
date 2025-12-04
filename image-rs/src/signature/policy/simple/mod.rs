// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use oci_client::secrets::RegistryAuth;
use serde::*;
use strum_macros::Display;
use strum_macros::EnumString;

use base64::Engine;

pub mod sigstore;
mod verify;
#[cfg(feature = "signature-simple-xrss")]
mod xrss;

use crate::signature::SignatureValidator;
use crate::signature::{image::Image, policy::ref_match::PolicyReqMatchType};

use super::SimpleParameters;

/// subdir of Sigstore Config file.
/// The reason for using the `/run` directory here is that in general HW-TEE,
/// the `/run` directory is mounted in `tmpfs`, which is located in the encrypted memory protected by HW-TEE.
pub const SIG_STORE_CONFIG_SUB_DIR: &str = "image-security/simple_signing/sigstore_config";

#[derive(Deserialize, EnumString, Display, Debug, PartialEq, Eq, Clone)]
pub enum KeyType {
    #[strum(to_string = "GPGKeys")]
    Gpg,
}

pub fn judge_single_signature(
    image: &Image,
    signed_identity: Option<&PolicyReqMatchType>,
    pubkey_ring: &[u8],
    sig: Vec<u8>,
) -> Result<()> {
    // Verify the signature with the pubkey ring.
    let sig_payload = verify::verify_sig_and_extract_payload(pubkey_ring, sig)?;

    // Verify whether the information recorded in signature payload
    // is consistent with the real information of the image.
    //
    // The match policy of image-reference is the "signedIdentity" field.
    // If the signedIdentity field is not set, by default will be set
    // `matchRepoDigestOrExact`
    let signed_identity = match signed_identity {
        Some(rule) => rule,
        None => &PolicyReqMatchType::MatchRepoDigestOrExact,
    };

    sig_payload.validate_signed_docker_reference(&image.reference, signed_identity)?;
    sig_payload.validate_signed_docker_manifest_digest(&image.manifest_digest.to_string())?;

    Ok(())
}

impl SignatureValidator {
    pub(crate) async fn simple_signing_allows_image(
        &self,
        parameters: &SimpleParameters,
        image: &Image,
        auth: &RegistryAuth,
    ) -> Result<()> {
        // TODO: only support "GPGKeys" type now.
        //
        // refer to https://github.com/confidential-containers/image-rs/issues/14
        if parameters.key_type != KeyType::Gpg.to_string() {
            bail!(
                "Unknown key type in policy config: only support {} now.",
                KeyType::Gpg
            );
        }

        let pubkey_ring = match (&parameters.key_path, &parameters.key_data) {
            (None, None) => bail!("Neither keyPath or keyData specified."),
            (Some(_), Some(_)) => bail!("Both keyPath and keyData specified."),
            (None, Some(key_data)) => base64::engine::general_purpose::STANDARD.decode(key_data)?,
            (Some(key_path), None) => self
                .resource_provider
                .get_resource(key_path)
                .await
                .map_err(|e| {
                    anyhow!("Read SignedBy keyPath failed: {:?}, path: {}", e, key_path)
                })?,
        };

        let sigs = self.get_signatures(image, auth).await?;
        let mut reject_reasons: Vec<anyhow::Error> = Vec::new();

        for sig in sigs.iter() {
            match judge_single_signature(
                image,
                parameters.signed_identity.as_ref(),
                &pubkey_ring,
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

        Err(anyhow!(
            "The signatures do not satisfied! Reject reason: {:?}",
            reject_reasons
        ))
    }

    async fn get_signatures(&self, image: &Image, _auth: &RegistryAuth) -> Result<Vec<Vec<u8>>> {
        let mut sigs: Vec<Vec<u8>> = Vec::new();
        let simple_signing_sigstore_config = self
            .simple_signing_sigstore_config
            .as_ref()
            .ok_or(anyhow!("Simple Signing Sigstore Config not set"))?;

        // Get image digest (manifest digest)
        let image_digest = if !image.manifest_digest.is_empty() {
            image.manifest_digest.clone()
        } else if let Some(d) = image.reference.digest() {
            d.try_into()?
        } else {
            bail!("Missing image digest");
        };

        #[cfg(feature = "signature-simple-xrss")]
        {
            let registry_client = xrss::RegistryClient::new();
            let mut registry_sigs = registry_client
                .get_signatures_from_registry(image, &image_digest, _auth)
                .await?;
            sigs.append(&mut registry_sigs);
            if *simple_signing_sigstore_config == sigstore::SigstoreConfig::default() {
                if sigs.is_empty() {
                    bail!("Missing sigstore config file and no signatures in registry");
                }

                return Ok(sigs);
            }
        }

        // Format the sigstore name: `image-repository@digest-algorithm=digest-value`.
        let sigstore_name = sigstore::format_sigstore_name(&image.reference, image_digest);

        let sigstore_base_url = simple_signing_sigstore_config
            .base_url(&image.reference)?
            .ok_or_else(|| anyhow!("The sigstore base url is none"))?;

        let sigstore = format!("{}/{}", &sigstore_base_url, &sigstore_name);
        let sigstore_uri = url::Url::parse(&sigstore)
            .map_err(|e| anyhow!("Failed to parse sigstore_uri: {:?}", e))?;

        let mut sigstore_sigs = sigstore::get_sigs_from_specific_sigstore(sigstore_uri).await?;
        sigs.append(&mut sigstore_sigs);

        Ok(sigs)
    }
}
