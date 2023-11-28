// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::{bail, Context, Ok, Result};
use codicon::Decoder;
use csv_rs::{
    api::guest::{AttestationReport, CsvGuest},
    certs::{ca, csv},
};
use serde::{Deserialize, Serialize};
use std::path::Path;

use hyper::body::HttpBody as _;
use hyper::Client;
use hyper_tls::HttpsConnector;

pub fn detect_platform() -> bool {
    Path::new("/dev/csv-guest").exists()
}

#[derive(Serialize, Deserialize)]
struct CertificateChain {
    hsk: ca::Certificate,
    cek: csv::Certificate,
    pek: csv::Certificate,
}

#[derive(Serialize, Deserialize)]
struct CsvEvidence {
    attestation_report: AttestationReport,
    cert_chain: CertificateChain,
    // Base64 Encoded CSV Serial Number (Used to identify HYGON chip ID)
    serial_number: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct CsvAttester {}

#[async_trait::async_trait]
impl Attester for CsvAttester {
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<String> {
        if report_data.len() > 64 {
            bail!("CSV Attester: Report data must be no more than 64 bytes");
        }
        report_data.resize(64, 0);

        let data = report_data.as_slice().try_into()?;
        let mut csv_guest = CsvGuest::open().unwrap();

        let (attestation_report, report_signer) = csv_guest.get_report(Some(data), None).unwrap();

        let cert_data = download_hskcek_from_kds(&report_signer.sn).await?;
        let mut cert_data = &cert_data[..];
        let hsk = ca::Certificate::decode(&mut cert_data, ()).unwrap();
        let cek = csv::Certificate::decode(&mut cert_data, ()).unwrap();
        let pek = csv::Certificate::decode(&mut &report_signer.pek_cert[..], ())?;

        let evidence = CsvEvidence {
            attestation_report,
            cert_chain: CertificateChain { hsk, cek, pek },
            serial_number: report_signer.sn.to_vec(),
        };
        serde_json::to_string(&evidence).context("Serialize CSV evidence failed")
    }
}

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
