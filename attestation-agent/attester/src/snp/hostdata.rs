// Copyright (c) 2024 Microsoft Corporation
// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use sev::firmware::guest::{AttestationReport, Firmware};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GetHostDataError {
    #[error("Open Sev guest firmware failed: {0}")]
    OpenSevGuestFirmware(#[from] std::io::Error),

    #[error("Get report failed: {0}")]
    GetReportError(#[from] sev::error::UserApiError),
}

pub fn get_snp_host_data() -> Result<[u8; 32], GetHostDataError> {
    let mut firmware = Firmware::open()?;
    let report_data: [u8; 64] = [0; 64];
    let report_bytes = firmware.get_report(None, Some(report_data), Some(0))?;
    let report = AttestationReport::from_bytes(&report_bytes)?;
    Ok(*report.host_data)
}
