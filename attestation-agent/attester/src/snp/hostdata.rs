// Copyright (c) 2024 Microsoft Corporation
// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::Path;

use sev::firmware::guest::{AttestationReport, Firmware};
use thiserror::Error;

use crate::tsm_report::{TSM_REPORT_PATH, TsmReportData, TsmReportError, TsmReportPath, TsmReportProvider};

#[derive(Error, Debug)]
pub enum GetHostDataError {
    #[error("Open Sev guest firmware failed: {0}")]
    OpenSevGuestFirmware(#[from] std::io::Error),

    #[error("Get report failed: {0}")]
    GetReportError(#[from] sev::error::UserApiError),

    #[error("Get TSM report failed: {0}")]
    GetTsmReportError(#[from] TsmReportError),
}

pub fn get_snp_host_data() -> Result<[u8; 32], GetHostDataError> {
    tracing::debug!("Getting SNP Host Data...");
    let report_data: [u8; 64] = [0; 64];
    let report_bytes: Vec<u8>;

    if Path::new(TSM_REPORT_PATH).exists() {
        tracing::debug!("TSM_REPORT_PATH file exists at {}", TSM_REPORT_PATH);
        // The VMPL value is set to 0, which means the report is generated at the highest privilege level.
        const VMPL: u8 = 0;

        // Get and verify the TSM Report path instance for SEV-SNP.
        let mut tsm_report_path = TsmReportPath::new(TsmReportProvider::Sev)?;

        // Generate the attestation report from the TSM Report path.
        report_bytes = tsm_report_path
            .attestation_report(TsmReportData::Sev(VMPL, report_data.to_vec()))?;
    } else {
        tracing::debug!("No file found at TSM_REPORT_PATH: {}", TSM_REPORT_PATH);
        tracing::debug!("sysfs for SEV-SNP is not supported, which requires kernel version >= 6.16.");
        let mut firmware = Firmware::open()?;
        report_bytes = firmware.get_report(None, Some(report_data), Some(0))?;
    }
    
    let report = AttestationReport::from_bytes(&report_bytes)?;
    Ok(*report.host_data)
}
