// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tdx_attest_rs;

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

impl Attester for TdxAttester {
    fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<String> {
        if report_data.len() > 64 {
            bail!("TDX Attester: Report data must be no more than 64 bytes");
        }

        report_data.resize(64, 0);

        let tdx_report_data = tdx_attest_rs::tdx_report_data_t {
            d: report_data.as_slice().try_into()?,
        };

        let quote = match tdx_attest_rs::tdx_att_get_quote(Some(&tdx_report_data), None, None, 0) {
            (tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS, Some(q)) => base64::encode(q),
            (error_code, _) => {
                return Err(anyhow!(
                    "TDX Attester: Failed to get TD quote. Error code: {:?}",
                    error_code
                ));
            }
        };

        let cc_eventlog = match std::fs::read(CCEL_PATH) {
            Result::Ok(el) => Some(base64::encode(el)),
            Result::Err(e) => {
                log::warn!("Read CC Eventlog failed: {:?}", e);
                None
            }
        };

        let evidence = TdxEvidence { cc_eventlog, quote };

        serde_json::to_string(&evidence)
            .map_err(|e| anyhow!("Serialize TDX evidence failed: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[test]
    fn test_tdx_get_evidence() {
        let attester = TdxAttester::default();
        let report_data: Vec<u8> = vec![0; 48];

        let evidence = attester.get_evidence(report_data);
        assert!(evidence.is_ok());
    }
}
