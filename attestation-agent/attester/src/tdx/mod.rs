// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::tsm_report::*;
use super::Attester;
use crate::utils::pad;
use crate::InitdataResult;
use anyhow::*;
use base64::Engine;
use scroll::Pread;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::mem;
use std::path::Path;
use tdx_attest_rs::tdx_report_t;

mod report;

const TDX_REPORT_DATA_SIZE: usize = 64;
const CCEL_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";
const RUNTIME_MEASUREMENT_RTMR_INDEX: u64 = 2;

pub fn detect_platform() -> bool {
    TsmReportPath::new(TsmReportProvider::Tdx).is_ok() || Path::new("/dev/tdx_guest").exists()
}

fn get_quote_ioctl(report_data: &Vec<u8>) -> Result<Vec<u8>> {
    let tdx_report_data = tdx_attest_rs::tdx_report_data_t {
        // report_data.resize() ensures copying report_data to
        // tdx_attest_rs::tdx_report_data_t cannot panic.
        d: report_data.as_slice().try_into().unwrap(),
    };

    match tdx_attest_rs::tdx_att_get_quote(Some(&tdx_report_data), None, None, 0) {
        (tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS, Some(q)) => Ok(q),
        (error_code, _) => Err(anyhow!(
            "TDX getquote ioctl: failed with error code: {:?}",
            error_code
        )),
    }
}

// Return true if the TD environment can extend runtime measurement,
// else false. The best guess at the moment is that if "TSM reports"
// is available, the TD runs Linux upstream kernel and is _currently_
// not able to do it.
fn runtime_measurement_extend_available() -> bool {
    if Path::new("/sys/kernel/config/tsm/report").exists() {
        return false;
    }

    true
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

        let quote_bytes = TsmReportPath::new(TsmReportProvider::Tdx).map_or_else(
            |notsm| {
                get_quote_ioctl(&report_data)
                    .context(format!("TDX Attester: quote generation using ioctl() fallback failed after a TSM report error ({notsm})"))
            },
            |tsm| {
                tsm.attestation_report(TsmReportData::Tdx(report_data.clone()))
                    .context("TDX Attester: quote generation using TSM reports failed")
            },
        )?;

        let engine = base64::engine::general_purpose::STANDARD;
        let quote = engine.encode(quote_bytes);

        let cc_eventlog = match std::fs::read(CCEL_PATH) {
            Result::Ok(el) => Some(engine.encode(el)),
            Result::Err(e) => {
                log::warn!("Read CC Eventlog failed: {:?}", e);
                None
            }
        };

        let evidence = TdxEvidence { cc_eventlog, quote };

        serde_json::to_string(&evidence).context("Serialize TDX evidence failed")
    }

    async fn extend_runtime_measurement(
        &self,
        events: Vec<Vec<u8>>,
        _register_index: Option<u64>,
    ) -> Result<()> {
        if !runtime_measurement_extend_available() {
            bail!("TDX Attester: Cannot extend runtime measurement on this system");
        }

        for event in events {
            let mut event_buffer = [0u8; mem::size_of::<tdx_attest_rs::tdx_rtmr_event_t>()];
            let mut hasher = Sha384::new();
            hasher.update(&event);
            let hash = hasher.finalize().to_vec();
            let rtmr_event = unsafe {
                &mut *(event_buffer.as_mut_ptr() as *mut tdx_attest_rs::tdx_rtmr_event_t)
            };
            rtmr_event.version = 1;
            rtmr_event.rtmr_index = RUNTIME_MEASUREMENT_RTMR_INDEX;
            rtmr_event.extend_data.copy_from_slice(&hash);
            match tdx_attest_rs::tdx_att_extend(&event_buffer) {
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

    async fn check_init_data(&self, init_data: &[u8]) -> Result<InitdataResult> {
        let mut report = tdx_report_t { d: [0; 1024] };
        match tdx_attest_rs::tdx_att_get_report(None, &mut report) {
            tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS => {
                log::debug!("Successfully get report")
            }
            error_code => {
                bail!(
                    "TDX Attester: Failed to get TD report. Error code: {:?}",
                    error_code
                );
            }
        };

        let td_report = report
            .d
            .pread::<report::TdReport>(0)
            .context("Parse TD report failed")?;

        let init_data: [u8; 48] = pad(init_data);
        if init_data != td_report.tdinfo.mrconfigid {
            bail!("Init data does not match!");
        }

        Ok(InitdataResult::Ok)
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
