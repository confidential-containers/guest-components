// Copyright (c) 2025 Confidential Containers Project Authors
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use num_traits::cast::FromPrimitive;
use serde::{Deserialize, Serialize};
use std::env;
use std::str::FromStr;
use tss_esapi::attributes::SessionAttributesBuilder;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{PcrHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::digest_values::DigestValues;
use tss_esapi::structures::{
    pcr_selection_list::PcrSelectionListBuilder, pcr_slot::PcrSlot, AttestInfo, PcrSelectionList,
    Signature, SignatureScheme as TpmSignatureScheme, SymmetricDefinition,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::Marshall;
use tss_esapi::Context as TssContext;
use tss_esapi::{
    abstraction::{pcr, public::DecodedKey},
    structures::HashScheme,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TpmQuote {
    pub signature: String,
    pub message: String,
    pub pcrs: Vec<String>,
}

const TPM_DEFAULT_AK_HANDLE: u32 = 0x81010002;
/// Environment variable to set a specific TPM device
const AA_TPM_DEVICE_ENV: &str = "AA_TPM_DEVICE";
/// Environment variable to set a non-default TPM AK handle
const AA_TPM_AK_HANDLE_ENV: &str = "AA_TPM_AK_HANDLE";

const TPM_QUOTE_PCR_SLOTS: [PcrSlot; 24] = [
    PcrSlot::Slot0,
    PcrSlot::Slot1,
    PcrSlot::Slot2,
    PcrSlot::Slot3,
    PcrSlot::Slot4,
    PcrSlot::Slot5,
    PcrSlot::Slot6,
    PcrSlot::Slot7,
    PcrSlot::Slot8,
    PcrSlot::Slot9,
    PcrSlot::Slot10,
    PcrSlot::Slot11,
    PcrSlot::Slot12,
    PcrSlot::Slot13,
    PcrSlot::Slot14,
    PcrSlot::Slot15,
    PcrSlot::Slot16,
    PcrSlot::Slot17,
    PcrSlot::Slot18,
    PcrSlot::Slot19,
    PcrSlot::Slot20,
    PcrSlot::Slot21,
    PcrSlot::Slot22,
    PcrSlot::Slot23,
];

/// Creates a TCTI configuration from a device path string.
pub fn create_tcti(tpm_device: &str) -> Result<TctiNameConf> {
    log::info!("Creating TCTI configuration for device: {}", tpm_device);
    let tcti_conf_str = format!("device:{}", tpm_device);
    TctiNameConf::from_str(&tcti_conf_str).context(format!(
        "Failed to create TCTI config from: {}",
        tcti_conf_str
    ))
}

/// Creates a TSS context without a session, for a specific TPM device.
pub fn create_ctx_without_session(tpm_device: &str) -> Result<TssContext> {
    let tcti = create_tcti(tpm_device)?;
    TssContext::new(tcti).context(format!(
        "Failed to create TSS context for device: {}",
        tpm_device
    ))
}

/// Creates a TSS context with a session, for a specific TPM device.
pub fn create_ctx_with_session(tpm_device: &str) -> Result<TssContext> {
    let mut ctx = create_ctx_without_session(tpm_device)?;

    let session = ctx.start_auth_session(
        None,
        None,
        None,
        SessionType::Hmac,
        SymmetricDefinition::Xor {
            hashing_algorithm: HashingAlgorithm::Sha256,
        },
        HashingAlgorithm::Sha256,
    )?;
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    let valid_session = session.ok_or(anyhow!("Failed to start auth session"))?;

    ctx.tr_sess_set_attributes(valid_session, session_attributes, session_attributes_mask)?;
    ctx.set_sessions((session, None, None));

    Ok(ctx)
}

pub fn create_pcr_selection_list(algorithm: &str) -> Result<PcrSelectionList> {
    match algorithm {
        "SHA256" => PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &TPM_QUOTE_PCR_SLOTS)
            .build()
            .context("PCR selection list build failed"),
        _ => bail!("Unsupported PCR Hash Algorithm"),
    }
}

/// Extend a PCR with the given digest at the given index.
pub fn extend_pcr(tpm_device: &str, digest: Vec<u8>, index: u64) -> Result<()> {
    let mut ctx = create_ctx_with_session(tpm_device)?;

    if index >= TPM_QUOTE_PCR_SLOTS.len() as u64 {
        bail!("PCR index out of bounds");
    }
    if digest.len() != 32 {
        bail!("Event digest length is not 32 bytes");
    }

    let pcr_handle = PcrHandle::from_u64(index).ok_or_else(|| anyhow!("Invalid pcr index"))?;
    let mut digest_values = DigestValues::new();
    digest_values.set(
        HashingAlgorithm::Sha256,
        digest
            .try_into()
            .map_err(|_| anyhow!("Failed to convert digest"))?,
    );
    ctx.pcr_extend(pcr_handle, digest_values)?;
    Ok(())
}

/// Read all PCRs for the given algorithm.
pub fn read_all_pcrs(tpm_device: &str, algorithm: &str) -> Result<Vec<String>> {
    let mut context = create_ctx_without_session(tpm_device)?;

    let selection_list = create_pcr_selection_list(algorithm)?;
    let pcr_data = pcr::read_all(&mut context, selection_list)?;
    let hashing_algorithm = match algorithm {
        "SHA256" => HashingAlgorithm::Sha256,
        _ => bail!("read_all_pcrs: Unsupported PCR algorithm of AA"),
    };
    let pcr_bank = pcr_data
        .pcr_bank(hashing_algorithm)
        .ok_or(anyhow!("PCR bank not found"))?;
    pcr_bank
        .into_iter()
        .map(|(_, digest)| Ok(hex::encode(digest.value())))
        .collect()
}

/// Function to generate a quote using a persistent AK handle
pub fn get_quote(
    tpm_device: &str,
    ak_handle_raw: u32,
    report_data: &[u8],
    pcr_algorithm: &str,
) -> Result<TpmQuote> {
    let mut context = create_ctx_with_session(tpm_device)?;

    // Create a KeyHandle object from ak_handle
    let tpm_handle: TpmHandle = ak_handle_raw.try_into()?;
    let ak_handle = context.tr_from_tpm_public(tpm_handle)?;

    let selection_list = create_pcr_selection_list(pcr_algorithm)?;

    let (attest, signature) = context
        .quote(
            ak_handle.into(),
            report_data.to_vec().try_into()?,
            TpmSignatureScheme::RsaSsa {
                hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
            },
            selection_list.clone(),
        )
        .context(format!(
            "TPM Quote API call failed for handle {:#X}",
            ak_handle_raw
        ))?;

    let AttestInfo::Quote { .. } = attest.attested() else {
        bail!("Get Quote failed");
    };
    let Signature::RsaSsa(_) = signature.clone() else {
        bail!("Wrong Signature");
    };

    let engine = base64::engine::general_purpose::STANDARD;
    drop(context);

    Ok(TpmQuote {
        signature: engine.encode(signature.marshall()?),
        message: engine.encode(attest.marshall()?),
        pcrs: read_all_pcrs(tpm_device, pcr_algorithm)?,
    })
}

/// Function to read the public part of the AK from the persistent handle
pub fn read_ak_public_key(tpm_device: &str, ak_handle_raw: u32) -> Result<Vec<u8>> {
    use picky_asn1_x509::SubjectPublicKeyInfo;
    let mut context = create_ctx_without_session(tpm_device)?;
    // Create a KeyHandle object from ak_handle_raw
    let tpm_handle: TpmHandle = ak_handle_raw.try_into()?;
    let ak_handle = context.tr_from_tpm_public(tpm_handle)?;

    let (ak_public, _, _) = context
        .read_public(ak_handle.into())
        .context("Failed to read AK public key from handle")?;

    // Decode the public key
    let decoded_key: DecodedKey = ak_public.try_into()?;
    let DecodedKey::RsaPublicKey(ak_pk_tss) = decoded_key else {
        bail!("AK is not an RSA key");
    };

    // Convert picky_asn1 v0.8.0 IntegerAsn1 (from tss-esapi) to v0.10.1 (from picky-asn1-x509)
    // Ref: https://docs.rs/picky-asn1/0.10.1/picky_asn1/wrapper/struct.IntegerAsn1.html#fields
    let modulus_bytes = ak_pk_tss.modulus.0;
    let exponent_bytes = ak_pk_tss.public_exponent.0;
    let modulus = picky_asn1::wrapper::IntegerAsn1(modulus_bytes);
    let public_exponent = picky_asn1::wrapper::IntegerAsn1(exponent_bytes);
    let ak_pk = SubjectPublicKeyInfo::new_rsa_key(modulus, public_exponent);
    let ak_pk_bytes = picky_asn1_der::to_vec(&ak_pk)?;
    Ok(ak_pk_bytes)
}

/// Detect the TPM device to use.
/// Priority: 1. AA_TPM_DEVICE env var, 2. /dev/tpm[0..2]
pub fn detect_tpm_device() -> Option<String> {
    // Check environment variable first
    if let Ok(dev) = env::var(AA_TPM_DEVICE_ENV) {
        return match std::path::Path::new(&dev).exists() {
            true => {
                log::info!(
                    "TPM device detected from {} env var: {}",
                    AA_TPM_DEVICE_ENV,
                    dev
                );
                Some(dev)
            }
            false => {
                log::warn!(
                    "{} env set to '{}', but device does not exist",
                    AA_TPM_DEVICE_ENV,
                    dev
                );
                None
            }
        };
    }

    // Check predefined TPM device paths
    for &dev in &["/dev/tpm0", "/dev/tpm1", "/dev/tpm2"] {
        if std::path::Path::new(dev).exists() {
            log::info!("TPM device detected: {}", dev);
            return Some(dev.to_string());
        }
    }

    log::warn!("No TPM device (/dev/tpm[0..2]) detected");
    None
}

// Function to get the persistent AK handle from an environment variable.
///
/// Reads the `AA_TPM_AK_HANDLE` environment variable and parses it as a hex u32 value.
/// If the variable is missing then uses the TPM_DEFAULT_AK_HANDLE
pub fn get_ak_handle() -> Option<u32> {
    let env_val = match env::var(AA_TPM_AK_HANDLE_ENV) {
        Ok(val) => val,
        Err(_) => {
            log::info!(
                "{} not set, using default handle: {:#X}",
                AA_TPM_AK_HANDLE_ENV,
                TPM_DEFAULT_AK_HANDLE
            );
            return Some(TPM_DEFAULT_AK_HANDLE);
        }
    };

    let stripped = env_val.trim_start_matches("0x");
    match u32::from_str_radix(stripped, 16) {
        Ok(handle) => {
            log::info!("AK handle detected from env: {:#X}", handle);
            Some(handle)
        }
        Err(e) => {
            log::warn!("Invalid AK handle '{}': {}", env_val, e);
            None
        }
    }
}
