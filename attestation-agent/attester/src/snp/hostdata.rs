// Copyright (c) 2024 Microsoft Corporation
// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::snp::vmpl::{VMPrivilegeLevel, set_privlevel};
use crate::tsm_report::{TsmReportData, TsmReportError, TsmReportPath, TsmReportProvider};
use sev::firmware::guest::{AttestationReport, Firmware};
use thiserror::Error;

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
    let report_data: [u8; 64] = [0; 64];
    let report_bytes: Vec<u8> = TsmReportPath::new(TsmReportProvider::Sev).map_or_else(
        |_notsm| {
            let mut firmware = Firmware::open()?;
            firmware
                .get_report(
                    None,
                    Some(report_data),
                    Some(VMPrivilegeLevel::default() as u32),
                )
                .map_err(GetHostDataError::from)
        },
        |tsm| {
            // Generate the attestation report from the TSM Report path.
            set_privlevel(&tsm, VMPrivilegeLevel::default())
                .map_err(GetHostDataError::from)?
                .attestation_report(TsmReportData::Sev(report_data.to_vec()))
                .map_err(GetHostDataError::from)
        },
    )?;

    let report = AttestationReport::from_bytes(&report_bytes)?;
    Ok(*report.host_data)
}
