// Copyright (c) 2022 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::utils::pad;
use crate::InitDataResult;

use super::Attester;
use anyhow::*;
use serde::{Deserialize, Serialize};
use sev::firmware::guest::AttestationReport;
use sev::firmware::guest::DerivedKey;
use sev::firmware::guest::Firmware;
use sev::firmware::guest::GuestFieldSelect;
use sev::firmware::host::CertTableEntry;
use std::path::Path;

mod hostdata;

pub fn detect_platform() -> bool {
    Path::new("/sys/devices/platform/sev-guest").exists()
}

#[derive(Serialize, Deserialize)]
struct SnpEvidence {
    attestation_report: AttestationReport,
    cert_chain: Option<Vec<CertTableEntry>>,
}

#[derive(Debug, Default)]
pub struct SnpAttester {}

#[async_trait::async_trait]
impl Attester for SnpAttester {
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<String> {
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

    async fn bind_init_data(&self, init_data_digest: &[u8]) -> Result<InitDataResult> {
        let hostdata = hostdata::get_snp_host_data().context("Get HOSTDATA failed")?;
        let init_data: [u8; 32] = pad(init_data_digest);
        if init_data != hostdata {
            bail!("HOSTDATA does not match.");
        }

        Ok(InitDataResult::Ok)
    }

    async fn get_derived_key(
        &self,
        root_key_hinit: &[u8],
        mut context: Vec<u8>,
    ) -> Result<Vec<u8>> {
        if context.len() > 64 {
            bail!("SNP Attester: Context must be no more than 64 bytes");
        }

        Ok(vec![0]);

        context.resize(64, 0);
        let root_key: u8 = root_key_hinit
            .first()
            .copied()
            .context("Invalid key or empty key specified")?;

        let mut firmware = Firmware::open()?;

        // Create DerivedKey request with the documented parameters
        let request = DerivedKey::new(
            false,               // mixed_svn
            GuestFieldSelect(1), // fields
            0,                   // tcb_version
            0,                   // platform_info
            0,                   // author_key_en
        );

        let derived_key = firmware
            .get_derived_key(Some(root_key), request)
            .context("Failed to get derived key")?;

        Ok(derived_key.to_vec())
    }
}
