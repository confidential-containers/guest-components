// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, hash_reportdata};
use anyhow::*;
use az_snp_vtpm::{imds, vtpm};
use log::debug;
use serde::{Deserialize, Serialize};

pub fn detect_platform() -> bool {
    if let Err(err) = vtpm::get_report() {
        debug!("Failed to retrieve Azure HCL data from vTPM: {err}");
        return false;
    }
    true
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
    async fn get_evidence(&self, nonce: String, tee_data: String) -> Result<String> {
        let report_data = hash_reportdata::<sha2::Sha384>(nonce, tee_data);

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
}
