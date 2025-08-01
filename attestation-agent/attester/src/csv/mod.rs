// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

//! # Hygon CSV Attester
//!
//! By default the attester will only get the attestation report from the hardware.
//! In some cases the verifier might not have network access. [`CSV_INCLUDE_CERT_CHAIN_ENV`]
//! env can be set to `true`, the attester will include the HSK and CEK cert in the
//! report and send to the verifier.

const CSV_INCLUDE_CERT_CHAIN_ENV: &str = "CSV_INCLUDE_CERT_CHAIN_IN_ATTESTATION_REPORT";

use crate::utils::read_eventlog;

use super::{Attester, TeeEvidence};
use anyhow::{bail, Context, Result};
use codicon::Decoder;
use csv_rs::{
    api::guest::{AttestationReport, AttestationReportWrapper, CsvGuest},
    certs::{ca, csv},
};
use hyper::{body::HttpBody, Client};
use hyper_tls::HttpsConnector;
use kbs_types::HashAlgorithm;
use log::debug;
use serde::{Deserialize, Serialize};
use std::path::Path;
pub fn detect_platform() -> bool {
    Path::new("/dev/csv-guest").exists()
}

#[derive(Serialize, Deserialize)]
struct HskCek {
    hsk: ca::Certificate,
    cek: csv::Certificate,
}

#[derive(Serialize, Deserialize)]
struct CertificateChain {
    #[serde(skip_serializing_if = "Option::is_none")]
    hsk_cek: Option<HskCek>,

    pek: csv::Certificate,
}

#[derive(Serialize, Deserialize)]
struct CsvEvidence {
    attestation_report: AttestationReportWrapper,

    cert_chain: CertificateChain,

    // Base64 Encoded CSV Serial Number (Used to identify HYGON chip ID)
    serial_number: Vec<u8>,

    /// Base64 encoded Eventlog
    /// This might include the
    /// - CCEL: <https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#cc-event-log-acpi-table>
    /// - AAEL in TCG2 encoding: <https://github.com/confidential-containers/trustee/blob/main/kbs/docs/confidential-containers-eventlog.md>
    cc_eventlog: Option<String>,
}

#[derive(Debug, Default)]
pub struct CsvAttester {}

async fn download_hskcek_from_kds(sn: &[u8]) -> Result<Vec<u8>> {
    let mut kds_url = String::from("https://cert.hygon.cn/hsk_cek?snumber=");
    let chip_id = std::str::from_utf8(sn)?.trim_end_matches('\0');

    kds_url += chip_id;

    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);

    let request = hyper::Request::builder()
        .uri(kds_url)
        .method(hyper::Method::GET)
        .header("User-Agent", "Hyper")
        .body(hyper::Body::empty())?;

    let response = client.request(request).await?;

    let mut response_body = Vec::new();
    let mut response = response.into_body();
    while let Some(chunk) = response.data().await {
        let chunk = chunk?;
        response_body.extend_from_slice(&chunk);
    }

    Ok(response_body)
}

#[async_trait::async_trait]
impl Attester for CsvAttester {
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<TeeEvidence> {
        if report_data.len() > 64 {
            bail!("CSV Attester: Report data must be no more than 64 bytes");
        }
        report_data.resize(64, 0);

        let data = report_data.as_slice().try_into()?;
        let mut csv_guest = CsvGuest::open()?;

        let attestation_report = csv_guest.get_report_ext(Some(data), None, 1)?;

        let report = AttestationReport::try_from(&attestation_report)?;
        let report_signer = report.signer();
        let pek = csv::Certificate::decode(&mut &report_signer.pek_cert[..], ())?;

        let hsk_cek = match std::env::var(CSV_INCLUDE_CERT_CHAIN_ENV) {
            Ok(v) if v == "true" => {
                debug!("hygon CSV attester: download HSK CEK from kds");
                let cert_data = download_hskcek_from_kds(&report_signer.sn).await?;
                let mut cert_data = &cert_data[..];
                let hsk = ca::Certificate::decode(&mut cert_data, ())?;
                let cek = csv::Certificate::decode(&mut cert_data, ())?;
                Some(HskCek { hsk, cek })
            }
            _ => None,
        };

        let cert_chain = CertificateChain { hsk_cek, pek };
        let cc_eventlog = read_eventlog().await?;
        let evidence = CsvEvidence {
            attestation_report,
            cert_chain,
            cc_eventlog,
            serial_number: report_signer.sn.to_vec(),
        };
        serde_json::to_value(&evidence).context("Serialize CSV evidence failed")
    }

    /// Extend TEE specific dynamic measurement register
    /// to enable dynamic measurement capabilities for input data at runtime.
    async fn extend_runtime_measurement(
        &self,
        event_digest: Vec<u8>,
        register_index: u64,
    ) -> Result<()> {
        let ccmr = self.pcr_to_ccmr(register_index);
        let mut csv_guest = CsvGuest::open()?;

        csv_guest.req_rtmr_extend(ccmr as u8, &event_digest)?;
        Ok(())
    }

    /// This function is used to get the runtime measurement registry value of
    /// the given PCR register index. Different platforms have different mapping
    /// relationship between PCR and platform RTMR.
    async fn get_runtime_measurement(&self, pcr_index: u64) -> Result<Vec<u8>> {
        let mut csv_guest = CsvGuest::open()?;
        let ccmr_index = self.pcr_to_ccmr(pcr_index);
        let bitmap = 1 << (ccmr_index);
        let (_, rtmr_read) = csv_guest.req_rtmr_read(bitmap)?;
        let reg_data = rtmr_read.get_read_reg(ccmr_index as usize);
        Ok(reg_data.to_vec())
    }

    /// This function is used to get the CC measurement register value of
    /// the given PCR register index. Different platforms have different mapping
    /// relationship between PCR and platform RTMR.
    fn pcr_to_ccmr(&self, pcr_index: u64) -> u64 {
        match pcr_index {
            0 => 0,
            1 | 7 => 1,
            2..=6 => 2,
            8..=15 => 3,
            _ => 4,
        }
    }

    fn ccel_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sm3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_csv_get_evidence() {
        let attester = CsvAttester::default();
        let report_data: Vec<u8> = vec![0; 64];

        let evidence = attester.get_evidence(report_data).await;
        assert!(evidence.is_ok());
    }
}
