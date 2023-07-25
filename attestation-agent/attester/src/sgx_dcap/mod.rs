// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::{anyhow, bail, Result};
use occlum_dcap::{sgx_report_data_t, DcapQuote};
use serde::{Deserialize, Serialize};

const OCCLUM_ENV: &str = "OCCLUM";

enum SgxLibOsType {
    Invalid,
    Occlum,
    Gramine,
}

fn get_libos_type() -> SgxLibOsType {
    if std::env::var(OCCLUM_ENV).is_ok() {
        return SgxLibOsType::Occlum;
    }

    match std::fs::read_to_string("/dev/attestation/attestation_type") {
        Ok(d) if d == "dcap" => SgxLibOsType::Gramine,
        _ => SgxLibOsType::Invalid,
    }
}

pub fn detect_platform() -> bool {
    match get_libos_type() {
        SgxLibOsType::Invalid => false,
        SgxLibOsType::Occlum => true,
        SgxLibOsType::Gramine => true,
    }
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

        let quote = match get_libos_type() {
            SgxLibOsType::Invalid => unimplemented!("empty quote"),
            SgxLibOsType::Occlum => {
                let mut handler = DcapQuote::new();
                let quote_size = handler.get_quote_size() as usize;
                let mut occlum_quote = Vec::new();

                occlum_quote.resize(quote_size, b'\0');

                match handler.generate_quote(
                    occlum_quote.as_mut_ptr(),
                    report_data_bin.as_ptr() as *const sgx_report_data_t,
                ) {
                    Ok(_) => occlum_quote,
                    Err(e) => bail!("generate quote: {e}"),
                }
            }
            SgxLibOsType::Gramine => {
                std::fs::write("/dev/attestation/user_report_data", report_data_bin)?;
                std::fs::read("/dev/attestation/quote")?
            }
        };

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
