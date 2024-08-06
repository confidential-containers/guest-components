// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::{bail, Context, Result};
use base64::Engine;
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

#[async_trait::async_trait]
impl Attester for SgxDcapAttester {
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<String> {
        if report_data.len() > 64 {
            bail!("SGX Attester: Report data should be SHA384 base64 String");
        }

        report_data.resize(64, 0);

        let quote = match get_libos_type() {
            SgxLibOsType::Invalid => unimplemented!("empty quote"),
            SgxLibOsType::Occlum => {
                let mut handler = DcapQuote::new()?;
                let quote_size = handler.get_quote_size()? as usize;
                let mut occlum_quote = Vec::new();

                occlum_quote.resize(quote_size, b'\0');

                match handler.generate_quote(
                    occlum_quote.as_mut_ptr(),
                    report_data.as_ptr() as *const sgx_report_data_t,
                ) {
                    Ok(_) => occlum_quote,
                    Err(e) => bail!("generate quote: {e}"),
                }
            }
            SgxLibOsType::Gramine => {
                std::fs::write("/dev/attestation/user_report_data", report_data)?;
                std::fs::read("/dev/attestation/quote")?
            }
        };

        let evidence = SgxDcapAttesterEvidence {
            quote: base64::engine::general_purpose::STANDARD.encode(quote),
        };

        serde_json::to_string(&evidence).context("Serialize SGX DCAP Attester evidence failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_sgx_get_evidence() {
        let attester = SgxDcapAttester::default();
        let report_data: Vec<u8> = vec![0; 48];

        let evidence = attester.get_evidence(report_data).await;
        assert!(evidence.is_ok());
    }
}
