// Copyright (c) 2025 Confidential Containers Project Authors
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Context;
use anyhow::*;
use base64::Engine;
use num_traits::cast::FromPrimitive;
use openssl::x509::X509;
use rsa as rust_rsa;
use serde::{Deserialize, Serialize};
use std::env;
use std::str::FromStr;
use tss_esapi::attributes::SessionAttributesBuilder;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::PcrHandle;
use tss_esapi::interface_types::algorithm::{
    AsymmetricAlgorithm, HashingAlgorithm, SignatureSchemeAlgorithm,
};
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::digest_values::DigestValues;
use tss_esapi::structures::{
    pcr_selection_list::PcrSelectionListBuilder, pcr_slot::PcrSlot, AttestInfo, PcrSelectionList,
    Private, Public, Signature, SignatureScheme as TpmSignatureScheme, SymmetricDefinition,
};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::Marshall;
use tss_esapi::Context as TssContext;
use tss_esapi::{
    abstraction::{
        ak::{create_ak, load_ak},
        ek::{create_ek_object, retrieve_ek_pubcert},
        pcr,
        public::DecodedKey,
        AsymmetricAlgorithmSelection, DefaultKey,
    },
    structures::HashScheme,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TpmQuote {
    pub signature: String,
    pub message: String,
    pub pcrs: Vec<String>,
}

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

pub fn create_tcti() -> Result<TctiNameConf> {
    log::info!("Creating TCTI configuration...");
    // The calleed must set the TCTI env variable to use a specific TPM device
    match env::var("TCTI") {
        std::result::Result::Err(_) => Ok(TctiNameConf::Device(DeviceConfig::default())),
        std::result::Result::Ok(tctistr) => Ok(TctiNameConf::from_str(&tctistr)?),
    }
}

pub fn create_ctx_without_session() -> Result<TssContext> {
    let tcti = create_tcti()?;
    let ctx = TssContext::new(tcti)?;
    Ok(ctx)
}

pub fn create_ctx_with_session() -> Result<TssContext> {
    let mut ctx = create_ctx_without_session()?;

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

// Extend a PCR with the given digest at the given index.
pub fn extend_pcr(digest: Vec<u8>, index: u64) -> Result<()> {
    let mut ctx = create_ctx_with_session()?;

    if index >= TPM_QUOTE_PCR_SLOTS.len() as u64 {
        bail!("PCR index out of bounds");
    }

    // Must be SHA-256 digest
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

// Read all PCRs for the given algorithm.
// Currently, only SHA256 is supported.
pub fn read_all_pcrs(algorithm: &str) -> Result<Vec<String>> {
    let mut context = create_ctx_without_session()?;

    let selection_list = create_pcr_selection_list(algorithm)?;

    let pcr_data = pcr::read_all(&mut context, selection_list)?;
    let hashing_algorithm = match algorithm {
        "SHA256" => HashingAlgorithm::Sha256,
        _ => bail!("read_all_pcrs: Unsupported PCR algorithm of AA"),
    };
    let pcr_bank = pcr_data
        .pcr_bank(hashing_algorithm)
        .ok_or(anyhow!("PCR bank not found"))?;

    let pcrs: Result<Vec<String>, _> = pcr_bank
        .into_iter()
        .map(|(_, digest)| Ok(hex::encode(digest.value())))
        .collect();
    let pcrs = pcrs?;

    Ok(pcrs)
}

#[derive(Clone)]
pub struct AttestationKey {
    pub ak_private: Private,
    pub ak_public: Public,
}

pub fn generate_rsa_ak() -> Result<AttestationKey> {
    let mut context = create_ctx_without_session()?;

    let ek_handle = create_ek_object(&mut context, AsymmetricAlgorithm::Rsa, DefaultKey)?;

    let ak = create_ak(
        &mut context,
        ek_handle,
        HashingAlgorithm::Sha256,
        SignatureSchemeAlgorithm::RsaSsa,
        None,
        DefaultKey,
    )?;

    Ok(AttestationKey {
        ak_private: ak.out_private,
        ak_public: ak.out_public,
    })
}

pub fn get_quote(
    attest_key: AttestationKey,
    report_data: &[u8],
    pcr_algorithm: &str,
) -> Result<TpmQuote> {
    let mut context = create_ctx_with_session()?;

    let ek_handle = create_ek_object(&mut context, AsymmetricAlgorithm::Rsa, DefaultKey)?;
    let ak_handle = load_ak(
        &mut context,
        ek_handle,
        None,
        attest_key.ak_private,
        attest_key.ak_public,
    )?;

    let selection_list = create_pcr_selection_list(pcr_algorithm)?;

    let (attest, signature) = context
        .quote(
            ak_handle,
            report_data.to_vec().try_into()?,
            TpmSignatureScheme::RsaSsa {
                hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
            },
            selection_list.clone(),
        )
        .context("TPM Quote API call failed")?;

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
        pcrs: read_all_pcrs(pcr_algorithm)?,
    })
}

pub fn get_ak_pub(ak: AttestationKey) -> Result<rust_rsa::RsaPublicKey> {
    let mut context = create_ctx_without_session()?;
    let ek_handle = create_ek_object(&mut context, AsymmetricAlgorithm::Rsa, DefaultKey)?;
    let key_handle = load_ak(
        &mut context,
        ek_handle,
        None,
        ak.clone().ak_private,
        ak.clone().ak_public,
    )?;
    let (pk, _, _) = context.read_public(key_handle)?;

    let decoded_key: DecodedKey = pk.try_into()?;
    let DecodedKey::RsaPublicKey(rsa_pk) = decoded_key else {
        bail!("unexpected key type");
    };

    let bytes = rsa_pk.modulus.as_unsigned_bytes_be();
    let n = rust_rsa::BigUint::from_bytes_be(bytes);
    let bytes = rsa_pk.public_exponent.as_unsigned_bytes_be();
    let e = rust_rsa::BigUint::from_bytes_be(bytes);

    let pkey = rust_rsa::RsaPublicKey::new(n, e)?;
    Ok(pkey)
}

pub fn dump_ek_cert_pem() -> Result<String> {
    let mut context = create_ctx_without_session()?;

    let ek_cert_bytes = retrieve_ek_pubcert(
        &mut context,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
    )?;
    let ek_cert_x509 = X509::from_der(&ek_cert_bytes)?;
    let ek_cert_pem_bytes = ek_cert_x509.to_pem()?;
    let ek_cert = String::from_utf8(ek_cert_pem_bytes)?;

    Ok(ek_cert)
}

/// Detect the TPM device to use.
///
/// Priority:
/// 1. If the TPM_DEVICE environment variable is set, use that.
/// 2. If /dev/tpm0 exists, use that.
/// 3. If /dev/tpm1 exists, use that.
/// 4. Otherwise, return None.
pub fn detect_tpm_device() -> Option<String> {
    if let Result::Ok(dev) = std::env::var("TPM_DEVICE") {
        if std::path::Path::new(&dev).exists() {
            log::info!("TPM device detected from TPM_DEVICE env: {}", dev);
            return Some(dev);
        } else {
            log::warn!("TPM_DEVICE env set to '{}', but device does not exist", dev);
        }
    }
    let candidates = ["/dev/tpm0", "/dev/tpm1"];
    for dev in candidates.iter() {
        if std::path::Path::new(dev).exists() {
            log::info!("TPM device detected: {}", dev);
            return Some(dev.to_string());
        }
    }
    log::warn!("No TPM device detected (checked TPM_DEVICE env, /dev/tpm0, and /dev/tpm1)");
    None
}
