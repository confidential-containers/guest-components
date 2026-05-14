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
use iocuddle::{Group, Ioctl, Write, WriteRead};
use kbs_types::HashAlgorithm;
use report::TdReport;
use scroll::Pread;
use serde::{Deserialize, Serialize};
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, path::Path};
use tracing::{debug, trace};

mod report;
mod rtmr;

const TDX_REPORT_DATA_SIZE: usize = 64;

/// `TDX_EXTEND_RTMR_DATA_LEN` / SHA384 digest size
const TDX_EXTEND_RTMR_DATA_LEN: usize = 48;

const TDX_GUEST_IOCTL: &str = "/dev/tdx_guest";

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
pub struct TdxAttester {}

#[repr(C)]
struct TdxReportReq {
    report_data: [u8; 64],
    d: [u8; 1024],
}

#[repr(C)]
struct TdxExtendRtmrReq {
    data: [u8; TDX_EXTEND_RTMR_DATA_LEN],
    index: u8,
}

const TDX: Group = Group::new(b'T');
const TDX_CMD_GET_REPORT0: Ioctl<WriteRead, &TdxReportReq> = unsafe { TDX.write_read(0x1) };

/// `_IOW('T', 3, struct tdx_extend_rtmr_req)` (DCAP `V3_DRIVER`).
const TDX_CMD_EXTEND_RTMR: Ioctl<Write, &TdxExtendRtmrReq> = unsafe { TDX.write(0x3) };

/// Pre-V3 DCAP used `_IOR` for the same `(type, nr)`; the encoded request differs from `_IOW`.
/// We still pass a user pointer for the kernel to read (`copy_from_user`), matching `ioctl_extend_rtmr`.
/// `lie` reuses the `_IOR` request number with iocuddle's `Write` ioctl wrapper (see iocuddle `Ioctl::lie`).
const TDX_CMD_EXTEND_RTMR_LEGACY: Ioctl<Write, &TdxExtendRtmrReq> =
    unsafe { TDX.read::<TdxExtendRtmrReq>(0x3).lie() };

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

    fn ioctl_write_rtmr(&self, index: u8, data: [u8; TDX_EXTEND_RTMR_DATA_LEN]) -> Result<()> {
        if index > 3 {
            bail!("TDX RTMR index {index} is invalid (allowed 0..=3)");
        }

        let extend_rtmr_req = TdxExtendRtmrReq { data, index };

        let mut fd = {
            let mut opts = OpenOptions::new();
            opts.read(true).write(true);
            opts.custom_flags(nix::libc::O_SYNC);
            opts.open(TDX_GUEST_IOCTL)
                .with_context(|| format!("open {TDX_GUEST_IOCTL} failed"))?
        };

        match TDX_CMD_EXTEND_RTMR.ioctl(&mut fd, &extend_rtmr_req) {
            std::result::Result::Ok(_) => Ok(()),
            std::result::Result::Err(e) if e.raw_os_error() == Some(nix::libc::ENOTTY) => {
                trace!("Write RTMR ioctl() (_IOW request) failed, falling back to legacy ioctl(_IOR request)");
                TDX_CMD_EXTEND_RTMR_LEGACY
                    .ioctl(&mut fd, &extend_rtmr_req)
                    .context("Write RTMR ioctl() (legacy _IOR request) failed")?;
                Ok(())
            }
            std::result::Result::Err(e) => bail!("Write RTMR ioctl() failed: {e}"),
        }
    }

    fn read_mrconfigid(&self) -> Result<Vec<u8>> {
        match TsmReportProvider::Tdx.read_initdata() {
            std::result::Result::Ok(mrconfigid) => return Ok(mrconfigid),
            Err(e) => debug!("Failed to read MRCONFIGID via sysfs, which requires kernel version >= 6.16. falling back to ioctl: {e}"),
        }

        let report = self.ioctl_get_report()?;
        let mrconfigid = report.get_mrconfigid();
        Ok(mrconfigid)
    }

    fn write_rtmr(&self, index: u64, data: [u8; 48]) -> Result<()> {
        match TsmReportProvider::Tdx.write_rtmr(index, &data) {
            std::result::Result::Ok(_) => return Ok(()),
            Err(e) => debug!("Failed to write RTMR via sysfs, which requires kernel version >= 6.16. falling back to ioctl: {e}"),
        }

        self.ioctl_write_rtmr(index as u8, data)?;
        Ok(())
    }

    fn read_rtmr(&self, index: u64) -> Result<Vec<u8>> {
        match TsmReportProvider::Tdx.read_rtmr(index) {
            std::result::Result::Ok(data) => return Ok(data),
            Err(e) => debug!("Failed to read RTMR via sysfs, which requires kernel version >= 6.16. falling back to ioctl: {e}"),
        }

        let report = self.ioctl_get_report()?;
        let rtmr = report.get_rtmr(index as usize);
        Ok(rtmr)
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
        true
    }

    async fn extend_runtime_measurement(
        &self,
        event_digest: Vec<u8>,
        register_index: u64,
    ) -> Result<()> {
        let ccmr_index = self.pcr_to_ccmr(register_index);
        let rtmr_index = ccmr_index - 1;

        let extend_data: [u8; 48] = pad(&event_digest);

        tracing::debug!(
            "TDX Attester: extend RTMR{rtmr_index}: {}",
            hex::encode(extend_data)
        );

        self.write_rtmr(rtmr_index, extend_data)?;

        Ok(())
    }

    async fn bind_init_data(&self, init_data_digest: &[u8]) -> Result<InitDataResult> {
        let mr_configid = self.read_mrconfigid()?;
        let mut init_data = init_data_digest.to_vec();
        init_data.resize(48, 0);
        if init_data != mr_configid {
            bail!("Init data does not match!");
        }

        Ok(InitDataResult::Ok)
    }

    async fn get_runtime_measurement(&self, pcr_index: u64) -> Result<Vec<u8>> {
        let ccmr = self.pcr_to_ccmr(pcr_index);
        let rtmr = self.read_rtmr(ccmr - 1)?;
        Ok(rtmr)
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
        let report_data: Vec<u8> = vec![0; 48];

        let evidence = attester.get_evidence(report_data).await;
        assert!(evidence.is_ok());
    }
}
