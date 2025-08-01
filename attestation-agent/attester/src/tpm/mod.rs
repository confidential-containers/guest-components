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

const PCR_SLOT_8: u64 = 8;
const TPM_REPORT_DATA_SIZE: usize = 64;

/// Evidence structure for the TPM Attester.
#[derive(Serialize, Deserialize, Debug)]
pub struct Evidence {
    pub report_data: String,
    pub tpm_quote: TpmQuote,
    pub ak_public: String,
}

/// TpmAttester struct holds the path to the detected TPM device.
#[derive(Debug, Default)]
pub struct TpmAttester {
    tpm_device: String,
}

impl TpmAttester {
    /// Creates a new TpmAttester.
    ///
    /// This function will detect the appropriate TPM device on the system once.
    /// It returns an error if no suitable TPM device is found.
    pub fn new() -> Result<Self> {
        let tpm_device = detect_tpm_device().ok_or_else(|| anyhow!("No TPM device found"))?;
        info!(
            "[TPM Attester] Initialized using TPM device: {}",
            &tpm_device
        );
        Ok(Self { tpm_device })
    }
}

/// Detects if the platform is supported by checking if a TpmAttester can be created.
pub fn detect_platform() -> bool {
    TpmAttester::new().is_ok()
}

#[async_trait::async_trait]
impl Attester for TpmAttester {
    /// Get evidence for the TPM attester.
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<TeeEvidence> {
        // Ensure report_data is exactly 64 bytes,
        // truncating if longer or padding with zeros if shorter
        report_data.resize(TPM_REPORT_DATA_SIZE, 0);

        let attestation_key = generate_rsa_ak(&self.tpm_device)?;
        let public = attestation_key.ak_public.marshall()?;
        let tpm_quote = get_quote(&self.tpm_device, attestation_key, &report_data, "SHA256")?;

        let evidence = Evidence {
            report_data: base64::engine::general_purpose::STANDARD.encode(&report_data),
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
        // Use the stored tpm_device path.
        extend_pcr(&self.tpm_device, event_digest, register_index)
            .map_err(|e| anyhow!("Failed to extend PCR: {e}"))
    }

    /// Bind init data for the TPM attester (extends PCR 8).
    async fn bind_init_data(&self, init_data_digest: &[u8]) -> Result<InitDataResult> {
        // Use the stored tpm_device path.
        extend_pcr(&self.tpm_device, init_data_digest.to_vec(), PCR_SLOT_8)
            .map_err(|e| anyhow!("Failed to extend PCR for init data: {e}"))?;
        Ok(InitDataResult::Ok)
    }

    /// Get runtime measurement (PCR value) for the given index.
    async fn get_runtime_measurement(&self, index: u64) -> Result<Vec<u8>> {
        // Use the stored tpm_device path.
        let pcrs = read_all_pcrs(&self.tpm_device, "SHA256")?;
        let idx = index as usize;
        let target_pcr = pcrs
            .get(idx)
            .ok_or_else(|| anyhow!("Register index out of bounds"))?;
        let pcr_value = hex::decode(target_pcr)?;
        Ok(pcr_value)
    }
}
