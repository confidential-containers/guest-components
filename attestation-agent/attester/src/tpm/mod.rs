// Copyright (c) 2025 Confidential Containers Project Authors
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, InitDataResult, TeeEvidence};
use crate::utils::truncate_digest;
pub mod utils;

use self::utils::{
    TpmQuote, detect_tpm_device, extend_pcr, get_ak_handle, get_quote, read_ak_public_key,
    read_all_pcrs,
};
use anyhow::{Result, anyhow};
use base64::Engine;
use kbs_types::Tee;
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;
use tracing::info;

const PCR_SLOT_8: u64 = 8;
const TPM_REPORT_DATA_SIZE: usize = 32;
const TPM_HASH_ALGORITHM: &str = "SHA256";

/// Evidence structure for the TPM Attester.
#[derive(Serialize, Deserialize, Debug)]
pub struct Evidence {
    pub tpm_quote: TpmQuote,
    pub ak_public: String,
}

/// TpmAttester struct holds the path to the detected TPM device.
#[derive(Debug, Default)]
pub struct TpmAttester {
    configuration: OnceCell<TpmConfiguration>,
}

#[derive(Debug)]
struct TpmConfiguration {
    tpm_device: String,
    ak_handle_raw: u32,
}

impl TpmAttester {
    /// Creates a new TpmAttester.
    ///
    /// This function will detect the appropriate TPM device on the system once.
    /// And also retrieve the AK handle.
    /// It returns an error if no suitable TPM device or AK handle is found.
    pub fn new() -> Result<Self> {
        Ok(Self {
            configuration: OnceCell::new_with(Some(Self::detect_configuration()?)),
        })
    }

    fn detect_configuration() -> Result<TpmConfiguration> {
        let tpm_device = detect_tpm_device().ok_or_else(|| anyhow!("No TPM device found"))?;
        let ak_handle_raw = get_ak_handle().ok_or_else(|| anyhow!("Failed to get AK handle"))?;
        info!(
            "[TPM Attester] Initialized using TPM device: {} and AK handle: {}",
            &tpm_device, &ak_handle_raw,
        );
        Ok(TpmConfiguration {
            tpm_device,
            ak_handle_raw,
        })
    }

    async fn configuration(&self) -> Result<&TpmConfiguration> {
        self.configuration
            .get_or_try_init(|| async { Self::detect_configuration() })
            .await
    }
}

impl std::fmt::Display for TpmAttester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("tpm-attester")
    }
}

#[async_trait::async_trait]
impl Attester for TpmAttester {
    /// Detects support by checking if a TpmAttester can be created.
    fn detect_tee(&self) -> Option<Tee> {
        TpmAttester::new().is_ok().then_some(Tee::Tpm)
    }

    /// Get evidence for the TPM attester.
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<TeeEvidence> {
        // Ensure report_data is exactly 64 bytes,
        // truncating if longer or padding with zeros if shorter
        report_data.resize(TPM_REPORT_DATA_SIZE, 0);
        let configuration = self.configuration().await?;
        let ak_public_bytes =
            read_ak_public_key(&configuration.tpm_device, configuration.ak_handle_raw)?;
        let tpm_quote = get_quote(
            &configuration.tpm_device,
            configuration.ak_handle_raw,
            &report_data,
            TPM_HASH_ALGORITHM,
        )?;

        let evidence = Evidence {
            tpm_quote,
            ak_public: base64::engine::general_purpose::STANDARD.encode(ak_public_bytes),
        };
        Ok(serde_json::to_value(&evidence)?)
    }

    fn supports_runtime_measurement(&self) -> bool {
        true
    }

    /// Extend runtime measurement for the TPM attester.
    async fn extend_runtime_measurement(
        &self,
        event_digest: Vec<u8>,
        register_index: u64,
    ) -> Result<()> {
        let configuration = self.configuration().await?;
        // Use the stored tpm_device path.
        extend_pcr(&configuration.tpm_device, event_digest, register_index)
            .map_err(|e| anyhow!("Failed to extend PCR: {e}"))?;
        Ok(())
    }

    /// Bind init data for the TPM attester (extends PCR 8).
    async fn bind_init_data(&self, init_data_digest: &[u8]) -> Result<InitDataResult> {
        let digest = truncate_digest::<32>(init_data_digest)?;
        let configuration = self.configuration().await?;
        // Use the stored tpm_device path.
        extend_pcr(&configuration.tpm_device, digest.to_vec(), PCR_SLOT_8)
            .map_err(|e| anyhow!("Failed to extend PCR for init data: {e}"))?;
        Ok(InitDataResult::Ok)
    }

    /// Get runtime measurement (PCR value) for the given index.
    async fn get_runtime_measurement(&self, index: u64) -> Result<Vec<u8>> {
        let configuration = self.configuration().await?;
        // Use the stored tpm_device path.
        let pcrs = read_all_pcrs(&configuration.tpm_device, TPM_HASH_ALGORITHM)?;
        let idx = index as usize;
        let target_pcr = pcrs
            .get(idx)
            .ok_or_else(|| anyhow!("Register index out of bounds"))?;
        let pcr_value = hex::decode(target_pcr)?;
        Ok(pcr_value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_does_not_initialize_tpm_configuration() {
        let attester = TpmAttester::default();
        assert!(attester.configuration.get().is_none());
        assert!(attester.supports_runtime_measurement());
        assert!(attester.configuration.get().is_none());
    }
}
