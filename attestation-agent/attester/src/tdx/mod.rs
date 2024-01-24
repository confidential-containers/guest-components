// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tdx_attest_rs;

const TDX_REPORT_DATA_SIZE: usize = 64;
const CCEL_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";

pub fn detect_platform() -> bool {
    Path::new("/dev/tdx-attest").exists() || Path::new("/dev/tdx-guest").exists()
}

#[derive(Serialize, Deserialize)]
struct TdxEvidence {
    // Base64 encoded CC Eventlog ACPI table
    // refer to https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#cc-event-log-acpi-table.
    cc_eventlog: Option<String>,
    // Base64 encoded TD quote.
    quote: String,
}

#[derive(Debug, Default)]
pub struct TdxAttester {}

#[async_trait::async_trait]
impl Attester for TdxAttester {
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<String> {
        if report_data.len() > TDX_REPORT_DATA_SIZE {
            bail!("TDX Attester: Report data must be no more than {TDX_REPORT_DATA_SIZE} bytes");
        }

        report_data.resize(TDX_REPORT_DATA_SIZE, 0);

        let tdx_report_data = tdx_attest_rs::tdx_report_data_t {
            // report_data.resize() ensures copying report_data to
            // tdx_attest_rs::tdx_report_data_t cannot panic.
            d: report_data.as_slice().try_into().unwrap(),
        };

        let engine = base64::engine::general_purpose::STANDARD;
        let quote = match tdx_attest_rs::tdx_att_get_quote(Some(&tdx_report_data), None, None, 0) {
            (tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS, Some(q)) => engine.encode(q),
            (error_code, _) => {
                return Err(anyhow!(
                    "TDX Attester: Failed to get TD quote. Error code: {:?}",
                    error_code
                ));
            }
        };

        let cc_eventlog = match std::fs::read(CCEL_PATH) {
            Result::Ok(el) => Some(engine.encode(el)),
            Result::Err(e) => {
                log::warn!("Read CC Eventlog failed: {:?}", e);
                None
            }
        };

        let evidence = TdxEvidence { cc_eventlog, quote };

        serde_json::to_string(&evidence)
            .map_err(|e| anyhow!("Serialize TDX evidence failed: {:?}", e))
    }

    async fn extend_runtime_measurement(
        &self,
        events: Vec<Vec<u8>>,
        _register_index: Option<u64>,
    ) -> Result<()> {
        for event in events {
            match tdx_attest_rs::tdx_att_extend(&event) {
                tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS => {
                    log::debug!("TDX extend runtime measurement succeeded.")
                }
                error_code => {
                    bail!(
                        "TDX Attester: Failed to extend RTMR. Error code: {:?}",
                        error_code
                    );
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_tdx_get_evidence() {
        let attester = TdxAttester::default();
        let report_data: Vec<u8> = vec![0; 48];

        let evidence = attester.get_evidence(report_data).await;
        assert!(evidence.is_ok());
    }
}
