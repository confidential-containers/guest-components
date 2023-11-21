// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, hash_reportdata};
use anyhow::*;
use serde::{Deserialize, Serialize};
use sev::firmware::guest::AttestationReport;
use sev::firmware::guest::Firmware;
use sev::firmware::host::CertTableEntry;
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
    async fn get_evidence(&self, nonce: String, tee_data: String) -> Result<String> {
        let mut report_data = hash_reportdata::<sha2::Sha384>(nonce, tee_data);

        if report_data.len() > 64 {
            bail!("SNP Attester: Report data must be no more than 64 bytes");
        }

        report_data.resize(64, 0);

        let mut firmware = Firmware::open()?;
        let data = report_data.as_slice().try_into()?;

        let (report, certs) = firmware
            .get_ext_report(None, Some(data), Some(0))
            .context("Failed to get attestation report")?;

        let evidence = SnpEvidence {
            attestation_report: report,
            cert_chain: certs,
        };

        serde_json::to_string(&evidence).context("Serialize SNP evidence failed")
    }
}
