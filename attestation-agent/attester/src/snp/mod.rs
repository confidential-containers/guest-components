// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
use serde::{Deserialize, Serialize};
use sev::firmware::guest::types::{AttestationReport, SnpReportReq};
use sev::firmware::guest::Firmware;
use sev::firmware::host::types::CertTableEntry;
use std::path::Path;

pub fn detect_platform() -> bool {
    Path::new("/sys/devices/platform/sev-guest").exists()
}

#[derive(Serialize, Deserialize)]
struct SnpEvidence {
    attestation_report: AttestationReport,
    cert_chain: Vec<CertTableEntry>,
}

#[derive(Debug, Default)]
pub struct SnpAttester {}

#[async_trait::async_trait]
impl Attester for SnpAttester {
    async fn get_evidence(&self, report_data: String) -> Result<String> {
        let mut report_data_bin = base64::decode(report_data)?;

        if report_data_bin.len() != 48 {
            bail!("Malformed SNP Evidence");
        }

        report_data_bin.extend([0; 16]);

        let mut firmware = Firmware::open()?;
        let report_request = SnpReportReq::new(Some(report_data_bin.as_slice().try_into()?), 0);

        let (report, certs) = firmware
            .snp_get_ext_report(None, report_request)
            .context("Failed to get attestation report")?;

        let evidence = SnpEvidence {
            attestation_report: report,
            cert_chain: certs,
        };

        serde_json::to_string(&evidence).context("Serialize SNP evidence failed")
    }
}
