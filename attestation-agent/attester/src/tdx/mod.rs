// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::tsm_report::*;
use super::{Attester, TeeEvidence};
use crate::utils::{pad, read_eventlog};
use crate::InitDataResult;
use anyhow::*;
use base64::Engine;
use iocuddle::{Group, Ioctl, WriteRead};
use kbs_types::HashAlgorithm;
use report::TdReport;
use scroll::Pread;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::debug;

mod report;
mod rtmr;

const TDX_REPORT_DATA_SIZE: usize = 64;

/// `TDX_REGISTER_LENGTH` / SHA384 digest size
const TDX_REGISTER_LENGTH: usize = 48;

const TDX_TSM_SYSFS_PATH: &str = "/sys/devices/virtual/misc/tdx_guest/measurements";
const TDX_GUEST_IOCTL: &str = "/dev/tdx_guest";

const LIBTDX_ENABLED: bool = cfg!(feature = "tdx-attest-dcap-ioctls");

pub fn detect_platform() -> bool {
    TsmReportPath::new(TsmReportProvider::Tdx).is_ok() || Path::new(TDX_GUEST_IOCTL).exists()
}

#[derive(Serialize, Deserialize)]
struct TdxEvidence {
    /// Base64 encoded Eventlog
    /// This might include the
    /// - CCEL: <https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#cc-event-log-acpi-table>
    /// - AAEL in TCG2 encoding: <https://github.com/confidential-containers/trustee/blob/main/kbs/docs/confidential-containers-eventlog.md>
    cc_eventlog: Option<String>,
    // Base64 encoded TD quote.
    quote: String,
}

#[derive(Debug, Default)]
pub struct TdxAttester {
    /// Linux TSM sysfs is used to read and write runtime measurement registers,
    /// and also read the registers like MRCONFIGID. This ability starts with kernel version 6.16.
    /// If the sysfs is not supported, the attester will use the ioctl to get the report
    /// and the registers.
    supports_tsm_measurements: bool,
}

impl TdxAttester {
    pub fn new() -> Self {
        let supports_tsm_measurements = Path::new(TDX_TSM_SYSFS_PATH).exists();
        if !supports_tsm_measurements {
            debug!("sysfs for TDX is not supported, which requires kernel version >= 6.16.");
        }

        Self {
            supports_tsm_measurements,
        }
    }
}

#[repr(C)]
struct TdxReportReq {
    report_data: [u8; 64],
    d: [u8; 1024],
}

const TDX: Group = Group::new(b'T');
const TDX_CMD_GET_REPORT0: Ioctl<WriteRead, &TdxReportReq> = unsafe { TDX.write_read(0x1) };

impl TdxAttester {
    fn ioctl_get_report(&self) -> Result<TdReport> {
        let mut report = TdxReportReq {
            report_data: [0; 64],
            d: [0; 1024],
        };
        let mut fd = std::fs::File::open(TDX_GUEST_IOCTL)
            .with_context(|| format!("open {TDX_GUEST_IOCTL} failed"))?;

        TDX_CMD_GET_REPORT0
            .ioctl(&mut fd, &mut report)
            .context("Get TD report via ioctl() failed")?;

        let td_report = report
            .d
            .pread::<report::TdReport>(0)
            .context("Parse TD report failed")?;

        Ok(td_report)
    }
}

#[async_trait::async_trait]
impl Attester for TdxAttester {
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<TeeEvidence> {
        if report_data.len() > TDX_REPORT_DATA_SIZE {
            bail!("TDX Attester: Report data must be no more than {TDX_REPORT_DATA_SIZE} bytes");
        }

        report_data.resize(TDX_REPORT_DATA_SIZE, 0);

        let quote_bytes = TsmReportPath::new(TsmReportProvider::Tdx)
            .context("TDX Attester: failed to create TSM Report path")?
            .attestation_report(TsmReportData::Tdx(report_data))?;

        let engine = base64::engine::general_purpose::STANDARD;
        let quote = engine.encode(quote_bytes);

        let cc_eventlog = read_eventlog().await?;

        let evidence = TdxEvidence { cc_eventlog, quote };

        serde_json::to_value(&evidence).context("Serialize TDX evidence failed")
    }

    fn supports_runtime_measurement(&self) -> bool {
        self.supports_tsm_measurements || LIBTDX_ENABLED
    }

    async fn extend_runtime_measurement(
        &self,
        event_digest: Vec<u8>,
        register_index: u64,
    ) -> Result<()> {
        let ccmr_index = self.pcr_to_ccmr(register_index);
        let rtmr_index = ccmr_index - 1;

        let extend_data: [u8; TDX_REGISTER_LENGTH] = pad(&event_digest);

        debug!(
            "TDX Attester: extend RTMR{rtmr_index}: {}",
            hex::encode(extend_data)
        );

        #[cfg(not(feature = "tdx-attest-dcap-ioctls"))]
        std::fs::write(
            Path::new(TDX_TSM_SYSFS_PATH).join(format!("rtmr{rtmr_index}:sha384")),
            extend_data,
        )
        .context("TDX Attester: failed to extend RTMR")?;

        #[cfg(feature = "tdx-attest-dcap-ioctls")]
        let event: Vec<u8> = rtmr::TdxRtmrEvent::default()
            .with_extend_data(extend_data)
            .with_rtmr_index(rtmr_index)
            .into();

        #[cfg(feature = "tdx-attest-dcap-ioctls")]
        match tdx_attest_rs::tdx_att_extend(&event) {
            tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS => {
                debug!("TDX extend runtime measurement succeeded.")
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
        let report = self.ioctl_get_report()?;
        let mut init_data = init_data_digest.to_vec();
        init_data.resize(TDX_REGISTER_LENGTH, 0);
        if init_data != report.tdinfo.mrconfigid.to_vec() {
            bail!("Init data does not match!");
        }

        Ok(InitDataResult::Ok)
    }

    async fn get_runtime_measurement(&self, pcr_index: u64) -> Result<Vec<u8>> {
        let ccmr = self.pcr_to_ccmr(pcr_index);
        let index = ccmr - 1;
        let report = self.ioctl_get_report()?;
        Ok(report.get_rtmr(index as usize))
    }

    fn pcr_to_ccmr(&self, pcr_index: u64) -> u64 {
        // The match follows https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md#td-event-log
        // and https://uefi.org/specs/UEFI/2.11/38_Confidential_Computing.html#intel-trust-domain-extension
        match pcr_index {
            1 | 7 => 1,
            2..=6 => 2,
            8..=15 => 3,
            _ => 4,
        }
    }

    fn ccel_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha384
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_tdx_get_evidence() {
        let attester = TdxAttester::default();
        let report_data: Vec<u8> = vec![0; TDX_REPORT_DATA_SIZE];

        let evidence = attester.get_evidence(report_data).await;
        assert!(evidence.is_ok());
    }

    #[ignore]
    #[tokio::test]
    async fn test_tdx_ioctl_get_report() {
        let attester = TdxAttester::default();
        let report = attester.ioctl_get_report();
        assert!(report.is_ok());
    }
}
