// Copyright (c) 2025 Confidential Containers Project Authors
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, InitDataResult, TeeEvidence};
use crate::tpm_utils::{
    detect_tpm_device, extend_pcr, generate_rsa_ak, get_quote, read_all_pcrs, TpmQuote,
};
use anyhow::*;
use base64::Engine;
use log::info;
use serde::{Deserialize, Serialize};
use tss_esapi::traits::Marshall;

/// Evidence structure for the TPM Attester.
#[derive(Serialize, Deserialize, Debug)]
pub struct Evidence {
    pub svn: String,
    pub report_data: String,
    pub tpm_quote: TpmQuote,
    pub ak_public: String,
}

#[derive(Debug, Default)]
pub struct TpmAttester;

pub fn detect_platform() -> bool {
    // Return true if TPM device is detected
    detect_tpm_device().is_some()
}

#[async_trait::async_trait]
impl Attester for TpmAttester {
    /// Get evidence for the TPM attester.
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<TeeEvidence> {
        let tpm_device = detect_tpm_device().ok_or_else(|| anyhow!("No TPM device found"))?;
        info!("[TPM Attester] Using TPM device: {}", tpm_device);
        std::env::set_var("TCTI", format!("device:{}", tpm_device));
        let data = if report_data.len() > 64 {
            &report_data[..64]
        } else {
            &report_data
        };
        let attestation_key = generate_rsa_ak()?;
        let public = attestation_key.ak_public.marshall()?;
        let tpm_quote = get_quote(attestation_key, data, "SHA256")?;
        let evidence = Evidence {
            svn: "1".to_string(),
            report_data: base64::engine::general_purpose::STANDARD.encode(data),
            tpm_quote,
            ak_public: base64::engine::general_purpose::STANDARD.encode(public),
        };
        Ok(serde_json::to_value(&evidence)?)
    }

    /// Extend runtime measurement for the TPM attester.
    async fn extend_runtime_measurement(
        &self,
        event_digest: Vec<u8>,
        register_index: u64,
    ) -> Result<()> {
        let tpm_device = detect_tpm_device().ok_or_else(|| anyhow!("No TPM device found"))?;
        info!("[TPM Attester] Using TPM device: {}", tpm_device);
        std::env::set_var("TCTI", format!("device:{}", tpm_device));
        extend_pcr(event_digest, register_index).map_err(|e| anyhow!("Failed to extend PCR: {e}"))
    }

    /// Bind init data for the TPM attester (extends PCR 8).
    async fn bind_init_data(&self, init_data_digest: &[u8]) -> Result<InitDataResult> {
        let tpm_device = detect_tpm_device().ok_or_else(|| anyhow!("No TPM device found"))?;
        info!("[TPM Attester] Using TPM device: {}", tpm_device);
        std::env::set_var("TCTI", format!("device:{}", tpm_device));
        extend_pcr(init_data_digest.to_vec(), 8)
            .map_err(|e| anyhow!("Failed to extend PCR for init data: {e}"))?;
        Ok(InitDataResult::Ok)
    }

    /// Get runtime measurement (PCR value) for the given index.
    async fn get_runtime_measurement(&self, pcr_index: u64) -> Result<Vec<u8>> {
        let tpm_device = detect_tpm_device().ok_or_else(|| anyhow!("No TPM device found"))?;
        info!("[TPM Attester] Using TPM device: {}", tpm_device);
        std::env::set_var("TCTI", format!("device:{}", tpm_device));
        let pcrs = read_all_pcrs("SHA256")?;
        let idx = pcr_index as usize;
        let target_pcr = pcrs
            .get(idx)
            .ok_or_else(|| anyhow!("Register index out of bounds"))?;
        let pcr_value = hex::decode(target_pcr)?;
        Ok(pcr_value)
    }
}
