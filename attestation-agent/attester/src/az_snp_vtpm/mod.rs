// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, InitDataResult, TeeEvidence};
use anyhow::{bail, Context, Result};
use az_snp_vtpm::{imds, is_snp_cvm, vtpm};
use kbs_types::HashAlgorithm;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, hex::Hex, serde_as};

type UrlSafeBase64 = Base64<serde_with::base64::UrlSafe>;

pub fn detect_platform() -> bool {
    match is_snp_cvm() {
        Ok(is_snp) => is_snp,
        Err(err) => {
            debug!("Failed to retrieve Azure HCL data from vTPM: {err}");
            false
        }
    }
}

#[derive(Debug, Default)]
pub struct AzSnpVtpmAttester;

const EVIDENCE_VERSION: u32 = 1;

/// TPM quote containing PCR values and attestation data.
///
/// # Fields (in hex representation)
/// - `signature` - RSA signature over the quote message
/// - `message` - TPM attestation structure containing nonce and PCR digest
/// - `pcrs` - SHA-256 PCR values (24 registers, 32 bytes each)
#[serde_as]
#[derive(Serialize, Deserialize)]
pub(crate) struct TpmQuote {
    #[serde_as(as = "Hex")]
    signature: Vec<u8>,
    #[serde_as(as = "Hex")]
    message: Vec<u8>,
    #[serde_as(as = "Vec<Hex>")]
    pcrs: Vec<Vec<u8>>,
}

impl TryFrom<vtpm::Quote> for TpmQuote {
    type Error = serde_json::Error;

    fn try_from(q: vtpm::Quote) -> Result<Self, Self::Error> {
        // Re-serialize through JSON to access private fields
        let json = serde_json::to_value(&q)?;
        serde_json::from_value(json)
    }
}

/// Attestation evidence for Azure SNP vTPM.
///
/// This struct contains all the cryptographic evidence needed to verify
/// that code is running in a genuine AMD SEV-SNP confidential VM on Azure.
///
/// # Fields (vcek + hcl_report in URL-safe base64 representation)
/// - `version` - Schema version for forward compatibility
/// - `tpm_quote` - TPM quote containing PCR values and a signature
/// - `hcl_report` - Hardware Compatibility Layer report containing the
///    Hardware attestation report from the AMD SEV-SNP platform
/// - `vcek` - Versioned Chip Endorsement Key certificate (DER-encoded)
#[serde_as]
#[derive(Serialize, Deserialize)]
struct Evidence {
    version: u32,
    tpm_quote: TpmQuote,
    #[serde_as(as = "UrlSafeBase64")]
    hcl_report: Vec<u8>,
    #[serde_as(as = "UrlSafeBase64")]
    vcek: Vec<u8>,
}

/// Convert a PEM-encoded certificate to DER format
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let (label, der) =
        pem_rfc7468::decode_vec(pem.as_bytes()).context("Failed to decode VCEK PEM")?;
    if label != "CERTIFICATE" {
        bail!("Expected CERTIFICATE label in PEM, got {}", label);
    }

    Ok(der)
}

#[async_trait::async_trait]
impl Attester for AzSnpVtpmAttester {
    async fn get_evidence(&self, report_data: Vec<u8>) -> anyhow::Result<TeeEvidence> {
        let hcl_report = vtpm::get_report()?;
        let quote = vtpm::get_quote(&report_data)?;
        let tpm_quote = TpmQuote::try_from(quote)?;
        let certs = imds::get_certs()?;
        let vcek = pem_to_der(&certs.vcek)?;

        let evidence = Evidence {
            version: EVIDENCE_VERSION,
            tpm_quote,
            hcl_report,
            vcek,
        };

        Ok(serde_json::to_value(&evidence)?)
    }

    fn supports_runtime_measurement(&self) -> bool {
        true
    }

    async fn bind_init_data(&self, init_data_digest: &[u8]) -> anyhow::Result<InitDataResult> {
        utils::extend_pcr(init_data_digest, utils::INIT_DATA_PCR)?;
        Ok(InitDataResult::Ok)
    }

    async fn extend_runtime_measurement(
        &self,
        event_digest: Vec<u8>,
        register_index: u64,
    ) -> Result<()> {
        utils::extend_pcr(&event_digest, register_index as u8)?;
        Ok(())
    }

    fn pcr_to_ccmr(&self, pcr_index: u64) -> u64 {
        pcr_index
    }

    fn ccel_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }

    // TODO: add get_runtime_measurement function
    // See https://github.com/confidential-containers/guest-components/issues/1201
}

pub(crate) mod utils {
    use super::*;

    pub const INIT_DATA_PCR: u8 = 8;

    pub fn extend_pcr(digest: &[u8], pcr: u8) -> Result<()> {
        let sha256_digest: [u8; 32] = digest.try_into().context("expected sha256 digest")?;
        if pcr > 23 {
            bail!("Invalid PCR index: {pcr}");
        }
        info!("Extending PCR {} with {}", pcr, hex::encode(sha256_digest));
        vtpm::extend_pcr(pcr, &sha256_digest)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    const TEST_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIB0zCCAXqgAwIBAgIJALg0
-----END CERTIFICATE-----";

    #[test]
    fn test_pem_to_der() {
        let der = pem_to_der(TEST_PEM).unwrap();
        // "MIIB0zCCAXqgAwIBAgIJALg0" decodes to these bytes
        assert_eq!(
            der,
            base64::engine::general_purpose::STANDARD
                .decode("MIIB0zCCAXqgAwIBAgIJALg0")
                .unwrap()
        );
    }

    #[test]
    fn test_tpm_quote_hex_serialization() {
        let json = serde_json::json!({
            "signature": "deadbeef",
            "message": "cafebabe",
            "pcrs": ["00112233", "44556677"]
        });

        let tpm_quote: TpmQuote = serde_json::from_value(json).unwrap();
        assert_eq!(tpm_quote.signature, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(tpm_quote.message, vec![0xca, 0xfe, 0xba, 0xbe]);
        assert_eq!(
            tpm_quote.pcrs,
            vec![vec![0x00, 0x11, 0x22, 0x33], vec![0x44, 0x55, 0x66, 0x77]]
        );
    }

    #[test]
    fn test_base64_urlsafe_serialization() {
        // URL-safe base64 of [0xde, 0xad, 0xbe, 0xef] is "3q2-7w=="
        // URL-safe base64 of [0xca, 0xfe, 0xba, 0xbe] is "yv66vg=="
        let json = serde_json::json!({
            "version": 1,
            "report": "3q2-7w==",
            "vcek": "yv66vg=="
        });

        #[serde_as]
        #[derive(Deserialize)]
        struct TestEvidence {
            version: u32,
            #[serde_as(as = "UrlSafeBase64")]
            report: Vec<u8>,
            #[serde_as(as = "UrlSafeBase64")]
            vcek: Vec<u8>,
        }

        let evidence: TestEvidence = serde_json::from_value(json).unwrap();
        assert_eq!(evidence.version, 1);
        assert_eq!(evidence.report, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(evidence.vcek, vec![0xca, 0xfe, 0xba, 0xbe]);

        #[serde_as]
        #[derive(Serialize)]
        struct TestEvidenceOut {
            #[serde_as(as = "UrlSafeBase64")]
            report: Vec<u8>,
        }

        let out = TestEvidenceOut {
            report: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let json_out = serde_json::to_value(&out).unwrap();
        assert_eq!(json_out["report"], "3q2-7w==");
    }
}
