// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::{anyhow, bail, Result};
use occlum_dcap::{sgx_report_data_t, DcapQuote};
use serde::{Deserialize, Serialize};

const OCCLUM_ENV: &str = "OCCLUM";

pub fn detect_platform() -> bool {
    std::env::var(OCCLUM_ENV).is_ok()
}

#[derive(Serialize, Deserialize)]
struct SgxDcapAttesterEvidence {
    /// Base64 encoded SGX quote.
    quote: String,
}

#[derive(Debug, Default)]
pub struct SgxDcapAttester {}

impl Attester for SgxDcapAttester {
    fn get_evidence(&self, report_data: String) -> Result<String> {
        let mut report_data_bin = base64::decode(report_data)?;
        if report_data_bin.len() != 48 {
            bail!("SGX Attester: Report data should be SHA384 base64 String");
        }

        report_data_bin.extend([0; 16]);
        let mut handler = DcapQuote::new();
        let quote_size = handler.get_quote_size() as usize;
        let mut quote = Vec::new();
        quote.resize(quote_size, b'\0');
        let _ = handler
            .generate_quote(
                quote.as_mut_ptr(),
                report_data_bin.as_ptr() as *const sgx_report_data_t,
            )
            .map_err(|e| anyhow!("generate quote: {e}"))?;

        let evidence = SgxDcapAttesterEvidence {
            quote: base64::encode(quote),
        };

        serde_json::to_string(&evidence)
            .map_err(|e| anyhow!("Serialize SGX DCAP Attester evidence failed: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[test]
    fn test_sgx_get_evidence() {
        let attester = SgxDcapAttester::default();
        let report_data: Vec<u8> = vec![0; 48];
        let report_data_base64 = base64::encode(report_data);

        let evidence = attester.get_evidence(report_data_base64);
        assert!(evidence.is_ok());
    }
}
