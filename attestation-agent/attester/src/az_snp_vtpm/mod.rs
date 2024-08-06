// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::{bail, Context, Result};
use az_snp_vtpm::{imds, is_snp_cvm, vtpm};
use log::{debug, info};
use serde::{Deserialize, Serialize};

pub fn detect_platform() -> bool {
    match is_snp_cvm() {
        Ok(is_snp) => is_snp,
        Err(err) => {
            debug!("Failed to retrieve Azure HCL data from vTPM: {}", err);
            false
        }
    }
}

#[derive(Debug, Default)]
pub struct AzSnpVtpmAttester;

#[derive(Serialize, Deserialize)]
struct Evidence {
    quote: vtpm::Quote,
    report: Vec<u8>,
    vcek: String,
}

#[async_trait::async_trait]
impl Attester for AzSnpVtpmAttester {
    async fn get_evidence(&self, report_data: Vec<u8>) -> anyhow::Result<String> {
        let report = vtpm::get_report()?;
        let quote = vtpm::get_quote(&report_data)?;
        let certs = imds::get_certs()?;
        let vcek = certs.vcek;

        let evidence = Evidence {
            quote,
            report,
            vcek,
        };

        Ok(serde_json::to_string(&evidence)?)
    }

    async fn extend_runtime_measurement(
        &self,
        event_digest: Vec<u8>,
        register_index: u64,
    ) -> Result<()> {
        let sha256_digest: [u8; 32] = event_digest
            .as_slice()
            .try_into()
            .context("expected sha256 digest")?;
        if register_index > 23 {
            bail!("Invalid PCR index: {}", register_index);
        }
        let pcr: u8 = register_index as u8;
        info!("Extending PCR {} with {}", pcr, hex::encode(sha256_digest));
        vtpm::extend_pcr(pcr, &sha256_digest)?;

        Ok(())
    }
}
