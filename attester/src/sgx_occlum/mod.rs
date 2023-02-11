// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::{anyhow, bail, Result};
use occlum_dcap::{sgx_report_data_t, DcapQuote};
use serde::{Deserialize, Serialize};
use std::path::Path;

const SGX_REPORT_DATA_SIZE: usize = 64;

pub fn detect_platform() -> bool {
    Path::new("/dev/sgx_enclave").exists() && Path::new("/dev/sgx_provision").exists()
}

#[derive(Serialize, Deserialize)]
struct SgxOcclumAttesterEvidence {
    /// Base64 encoded SGX quote.
    quote: String,
}

#[derive(Debug, Default)]
pub struct SgxOcclumAttester {}

impl Attester for SgxOcclumAttester {
    fn get_evidence(&self, report_data: String) -> Result<String> {
        let mut report_data = report_data.as_bytes().to_vec();
        if report_data.len() > SGX_REPORT_DATA_SIZE {
            bail!("report data should be less than 64 bytes");
        }

        report_data.resize(SGX_REPORT_DATA_SIZE, b'\0');
        let mut handler = DcapQuote::new();
        let quote_size = handler.get_quote_size() as usize;
        let mut quote = Vec::new();
        quote.resize(quote_size, b'\0');
        let _ = handler
            .generate_quote(
                quote.as_mut_ptr(),
                report_data.as_ptr() as *const sgx_report_data_t,
            )
            .map_err(|e| anyhow!("generate quote: {e}"))?;

        let evidence = SgxOcclumAttesterEvidence {
            quote: base64::encode(quote),
        };

        serde_json::to_string(&evidence)
            .map_err(|e| anyhow!("Serialize SGX-Occlum evidence failed: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[test]
    fn test_sgx_get_evidence() {
        let attester = SgxOcclumAttester::default();
        let report_data: Vec<u8> = vec![0; SGX_REPORT_DATA_SIZE];
        let report_data_base64 = base64::encode(report_data);

        let evidence = attester.get_evidence(report_data_base64);
        assert!(evidence.is_ok());
    }
}
