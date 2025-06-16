// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::tsm_report::*;
use super::Attester;
use crate::utils::pad;
use crate::InitDataResult;
use anyhow::*;
use base64::Engine;
use iocuddle::{Group, Ioctl, WriteRead};
use report::TdReport;
use scroll::Pread;
use serde::{Deserialize, Serialize};
use std::path::Path;

mod report;
mod rtmr;

const TDX_REPORT_DATA_SIZE: usize = 64;
const CCEL_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";
const TDX_GUEST_IOCTL: &str = "/dev/tdx_guest";

pub fn detect_platform() -> bool {
    TsmReportPath::new(TsmReportProvider::Tdx).is_ok() || Path::new(TDX_GUEST_IOCTL).exists()
}

#[allow(unused_variables)]
fn get_quote_ioctl(report_data: &[u8]) -> Result<Vec<u8>> {
    cfg_if::cfg_if! {
            if #[cfg(feature = "tdx-attest-dcap-ioctls")] {
                let tdx_report_data = tdx_attest_rs::tdx_report_data_t {
                    // report_data.resize() ensures copying report_data to
                    // tdx_attest_rs::tdx_report_data_t cannot panic.
                    d: report_data.try_into().unwrap(),
                };

                match tdx_attest_rs::tdx_att_get_quote(Some(&tdx_report_data), None, None, 0) {
                    (tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS, Some(q)) => Ok(q),
                    (error_code, _) => Err(anyhow!(
                        "TDX DCAP get_quote: failed with error code: {:?}",
                        error_code
                    )),
                }
            } else {
                Err(anyhow!("TDX DCAP ioctls: support not available"))
        }
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

pub const DEFAULT_EVENTLOG_PATH: &str = "/run/attestation-agent/eventlog";

#[derive(Serialize, Deserialize)]
struct TdxEvidence {
    // Base64 encoded CC Eventlog ACPI table
    // refer to https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#cc-event-log-acpi-table.
    cc_eventlog: Option<String>,
    // Base64 encoded TD quote.
    quote: String,
    // Eventlog of Attestation Agent
    aa_eventlog: Option<String>,
}

#[derive(Debug, Default)]
pub struct TdxAttester {}

#[repr(C)]
struct TdxReportReq {
    report_data: [u8; 64],

    d: [u8; 1024],
}

impl Default for TdxReportReq {
    fn default() -> Self {
        Self {
            report_data: [0; 64],
            d: [0; 1024],
        }
    }
}

const TDX: Group = Group::new(b'T');
const TDX_CMD_GET_REPORT0: Ioctl<WriteRead, &TdxReportReq> = unsafe { TDX.write_read(0x1) };

impl TdxAttester {
    fn get_report() -> Result<TdReport> {
        let mut report = TdxReportReq::default();
        let mut fd =
            std::fs::File::open(TDX_GUEST_IOCTL).context("Open TD report ioctl() failed")?;

        TDX_CMD_GET_REPORT0
            .ioctl(&mut fd, &mut report)
            .context("Get TD report ioctl() failed")?;

        let td_report = report
            .d
            .pread::<report::TdReport>(0)
            .context("Parse TD report failed")?;

        Ok(td_report)
    }

    fn pcr_to_rtmr(register_index: u64) -> u64 {
        // The match follows https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md#td-event-log
        match register_index {
            1 | 7 => 0,
            2..=6 => 1,
            8..=15 => 2,
            _ => 3,
        }
    }
}

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

        let aa_eventlog = match std::fs::read_to_string(DEFAULT_EVENTLOG_PATH) {
            Result::Ok(el) => Some(el),
            Result::Err(e) => {
                log::warn!("Read AA Eventlog failed: {:?}", e);
                None
            }
        };

        let evidence = TdxEvidence {
            cc_eventlog,
            quote,
            aa_eventlog,
        };

        serde_json::to_string(&evidence).context("Serialize TDX evidence failed")
    }

    async fn extend_runtime_measurement(
        &self,
        event_digest: Vec<u8>,
        register_index: u64,
    ) -> Result<()> {
        if !runtime_measurement_extend_available() {
            bail!("TDX Attester: Cannot extend runtime measurement on this system");
        }

        let rtmr_index = Self::pcr_to_rtmr(register_index);

        let extend_data: [u8; 48] = pad(&event_digest);

        log::debug!(
            "TDX Attester: extend RTRM{rtmr_index}: {}",
            hex::encode(extend_data)
        );

        #[cfg(feature = "tdx-attest-dcap-ioctls")]
        let event: Vec<u8> = rtmr::TdxRtmrEvent::default()
            .with_extend_data(extend_data)
            .with_rtmr_index(rtmr_index)
            .into();

        #[cfg(feature = "tdx-attest-dcap-ioctls")]
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

        Ok(())
    }

    async fn bind_init_data(&self, init_data_digest: &[u8]) -> Result<InitDataResult> {
        let td_report = Self::get_report()?;
        let init_data: [u8; 48] = pad(init_data_digest);
        if init_data != td_report.tdinfo.mrconfigid {
            bail!("Init data does not match!");
        }

        Ok(InitDataResult::Ok)
    }

    async fn get_runtime_measurement(&self, pcr_index: u64) -> Result<Vec<u8>> {
        let td_report = Self::get_report()?;
        let rtmr_index = Self::pcr_to_rtmr(pcr_index) as usize;

        Ok(td_report.get_rtmr(rtmr_index))
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
    #[ignore]
    #[tokio::test]
    async fn test_tdx_get_report() {
        assert!(TdxAttester::get_report().is_ok());
    }
}
