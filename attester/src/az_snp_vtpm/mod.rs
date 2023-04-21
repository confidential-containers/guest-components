// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
use az_snp_vtpm::vtpm;
use serde::{Deserialize, Serialize};

pub fn detect_platform() -> bool {
    vtpm::has_tpm_device()
}

#[derive(Debug, Default)]
pub struct AzSnpVtpmAttester;

#[derive(Serialize, Deserialize)]
struct Evidence {
    quote: vtpm::Quote,
    report: Vec<u8>,
}

impl Attester for AzSnpVtpmAttester {
    fn get_evidence(&self, report_data: String) -> Result<String> {
        let report = vtpm::get_report()?;
        let report_data_bin = base64::decode(report_data)?;
        let quote = vtpm::get_quote(&report_data_bin)?;

        let evidence = Evidence { quote, report };

        Ok(serde_json::to_string(&evidence)?)
    }
}
