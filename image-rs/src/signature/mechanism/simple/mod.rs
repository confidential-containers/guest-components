// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use async_trait::async_trait;
use oci_distribution::secrets::RegistryAuth;
use serde::*;
use strum_macros::Display;
use strum_macros::EnumString;

#[cfg(feature = "signature-simple")]
mod sigstore;
#[cfg(feature = "signature-simple")]
mod verify;

use crate::signature::{image::Image, mechanism::Paths, policy::ref_match::PolicyReqMatchType};

use super::SignScheme;

#[derive(Deserialize, Debug, PartialEq, Eq, Serialize, Default)]
pub struct SimpleParameters {
    // KeyType specifies what kind of the public key to verify the signatures.
    #[serde(rename = "keyType")]
    pub key_type: String,

    // KeyPath is a pathname to a local file containing the trusted key(s).
    // Exactly one of KeyPath and KeyData can be specified.
    //
    // This field is optional.
    #[serde(rename = "keyPath")]
    pub key_path: Option<String>,
    // KeyData contains the trusted key(s), base64-encoded.
    // Exactly one of KeyPath and KeyData can be specified.
    //
    // This field is optional.
    #[serde(rename = "keyData")]
    pub key_data: Option<String>,

    // SignedIdentity specifies what image identity the signature must be claiming about the image.
    // Defaults to "match-exact" if not specified.
    //
    // This field is optional.
    #[serde(default, rename = "signedIdentity")]
    pub signed_identity: Option<PolicyReqMatchType>,

    /// Sigstore config file
    #[cfg(feature = "signature-simple")]
    #[serde(skip)]
    pub(crate) sig_store_config_file: sigstore::SigstoreConfig,
}

/// Prepare directories for configs and sigstore configs.
/// It will create (if not) the following dirs:
/// * [`SIG_STORE_CONFIG_DIR`]
#[cfg(feature = "signature-simple")]
async fn prepare_runtime_dirs(sig_store_config_dir: &str) -> Result<()> {
    if !std::path::Path::new(sig_store_config_dir).exists() {
        tokio::fs::create_dir_all(sig_store_config_dir)
            .await
            .map_err(|e| anyhow!("Create Simple Signing sigstore-config dir failed: {:?}", e))?;
    }
    Ok(())
}

#[async_trait]
impl SignScheme for SimpleParameters {
    /// Init simple scheme signing
    #[cfg(feature = "signature-simple")]
    async fn init(&mut self, config: &Paths) -> Result<()> {
        prepare_runtime_dirs(crate::config::SIG_STORE_CONFIG_DIR).await?;
        self.initialize_sigstore_config().await?;
        let sig_store_config_file = crate::resource::get_resource(&config.sigstore_config).await?;
        let sig_store_config_file =
            serde_yaml::from_slice::<sigstore::SigstoreConfig>(&sig_store_config_file)?;
        self.sig_store_config_file
            .update_self(sig_store_config_file)?;
        Ok(())
    }

    #[cfg(not(feature = "signature-simple"))]
    async fn init(&mut self, _config: &Paths) -> Result<()> {
        Ok(())
    }

    #[cfg(feature = "signature-simple")]
    async fn allows_image(&self, image: &mut Image, _auth: &RegistryAuth) -> Result<()> {
        use base64::Engine;
        // FIXME: only support "GPGKeys" type now.
        //
        // refer to https://github.com/confidential-containers/image-rs/issues/14
        if self.key_type != KeyType::Gpg.to_string() {
            bail!(
                "Unknown key type in policy config: only support {} now.",
                KeyType::Gpg.to_string()
            );
        }

        let pubkey_ring = match (&self.key_path, &self.key_data) {
            (None, None) => bail!("Neither keyPath or keyData specified."),
            (Some(_), Some(_)) => bail!("Both keyPath and keyData specified."),
            (None, Some(key_data)) => base64::engine::general_purpose::STANDARD.decode(key_data)?,
            (Some(key_path), None) => {
                crate::resource::get_resource(key_path).await.map_err(|e| {
                    anyhow!("Read SignedBy keyPath failed: {:?}, path: {}", e, key_path)
                })?
            }
        };

        let sigs = self.get_signatures(image).await?;
        let mut reject_reasons: Vec<anyhow::Error> = Vec::new();

        for sig in sigs.iter() {
            match judge_single_signature(
                image,
                self.signed_identity.as_ref(),
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

    #[cfg(not(feature = "signature-simple"))]
    async fn allows_image(&self, _image: &mut Image, _auth: &RegistryAuth) -> Result<()> {
        bail!("feature \"signature-simple\" not enabled.")
    }
}

#[derive(Deserialize, EnumString, Display, Debug, PartialEq, Eq, Clone)]
pub enum KeyType {
    #[strum(to_string = "GPGKeys")]
    Gpg,
}

#[cfg(feature = "signature-simple")]
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

#[cfg(feature = "signature-simple")]
impl SimpleParameters {
    /// Set the content of sigstore config with files in
    /// [`crate::config::SIG_STORE_CONFIG_DIR`]
    pub async fn initialize_sigstore_config(&mut self) -> Result<()> {
        // If the registry support `X-Registry-Supports-Signatures` API extension,
        // try to get signatures from the registry first.
        // Else, get signatures from "sigstore" according to the sigstore config file.
        // (https://github.com/containers/image/issues/384)
        //
        // TODO: Add get signatures from registry X-R-S-S API extension.
        //
        // issue: https://github.com/confidential-containers/image-rs/issues/12
        let sigstore_config =
            sigstore::SigstoreConfig::new_from_configs(crate::config::SIG_STORE_CONFIG_DIR).await?;
        self.sig_store_config_file.update_self(sigstore_config)?;

        Ok(())
    }

    pub async fn get_signatures(&self, image: &Image) -> Result<Vec<Vec<u8>>> {
        // Get image digest (manifest digest)
        let image_digest = if !image.manifest_digest.is_empty() {
            image.manifest_digest.clone()
        } else if let Some(d) = image.reference.digest() {
            d.try_into()?
        } else {
            bail!("Missing image digest");
        };

        // Format the sigstore name: `image-repository@digest-algorithm=digest-value`.
        let sigstore_name = sigstore::format_sigstore_name(&image.reference, image_digest);

        let sigstore_base_url = self
            .sig_store_config_file
            .base_url(&image.reference)?
            .ok_or_else(|| anyhow!("The sigstore base url is none"))?;

        let sigstore = format!("{}/{}", &sigstore_base_url, &sigstore_name);
        let sigstore_uri = url::Url::parse(&sigstore)
            .map_err(|e| anyhow!("Failed to parse sigstore_uri: {:?}", e))?;

        let sigs = sigstore::get_sigs_from_specific_sigstore(sigstore_uri).await?;

        Ok(sigs)
    }
}
