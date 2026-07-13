// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, InitDataResult, TeeEvidence};
use crate::az_snp_vtpm::{utils, TpmQuote};
use anyhow::*;
use az_tdx_vtpm::{hcl, imds, is_tdx_cvm, vtpm};
use kbs_types::HashAlgorithm;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use std::result::Result::Ok;
use tracing::debug;

type UrlSafeBase64 = Base64<serde_with::base64::UrlSafe>;

pub fn detect_platform() -> bool {
    match is_tdx_cvm() {
        Ok(tdx) => tdx,
        Err(err) => {
            debug!("Couldn't perform Azure TDX platform detection: {err}");
            false
        }
    }
}

#[derive(Debug, Default)]
pub struct AzTdxVtpmAttester;

const EVIDENCE_VERSION: u32 = 1;

/// Attestation evidence for Azure TDX vTPM.
///
/// This struct contains all the cryptographic evidence needed to verify
/// that code is running in a genuine Intel TDX confidential VM on Azure.
///
/// # Fields (hcl_report and td_quote are base64-url encoded)
/// - `version` - Schema version for forward compatibility
/// - `tpm_quote` - TPM quote containing PCR values and a signature
/// - `hcl_report` - Hardware Compatibility Layer report containing the TD report
/// - `td_quote` - Intel TDX quote signed by the Quoting Enclave
#[serde_as]
#[derive(Serialize, Deserialize)]
struct Evidence {
    version: u32,
    tpm_quote: TpmQuote,
    #[serde_as(as = "UrlSafeBase64")]
    hcl_report: Vec<u8>,
    #[serde_as(as = "UrlSafeBase64")]
    td_quote: Vec<u8>,
}

#[async_trait::async_trait]
impl Attester for AzTdxVtpmAttester {
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<TeeEvidence> {
        let hcl_report_bytes = vtpm::get_report_with_report_data(&report_data)?;
        let hcl_report = hcl::HclReport::new(hcl_report_bytes.clone())?;
        let td_report = hcl_report.try_into()?;
        let td_quote = imds::get_td_quote(&td_report)?;
        let tpm_quote = vtpm::get_quote(&report_data)?.into();

        let evidence = Evidence {
            version: EVIDENCE_VERSION,
            tpm_quote,
            hcl_report: hcl_report_bytes,
            td_quote,
        };
        Ok(serde_json::to_value(&evidence)?)
    }

    async fn bind_init_data(&self, init_data_digest: &[u8]) -> anyhow::Result<InitDataResult> {
        utils::extend_pcr(init_data_digest, utils::INIT_DATA_PCR)?;
        Ok(InitDataResult::Ok)
    }

    fn supports_runtime_measurement(&self) -> bool {
        true
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
