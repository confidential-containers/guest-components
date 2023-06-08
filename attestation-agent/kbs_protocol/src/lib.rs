// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use async_trait::async_trait;
use attester::{detect_tee_type, Attester};
use core::time::Duration;
use crypto::{hash_chunks, TeeKey};
use kbs_types::{Attestation, ErrorInformation};
use types::*;
use url::Url;

pub mod types;

const KBS_REQ_TIMEOUT_SEC: u64 = 60;
const KBS_GET_RESOURCE_MAX_ATTEMPT: u64 = 3;

pub const KBS_URL_PREFIX: &str = "kbs/v0";

#[async_trait]
pub trait KbsRequest {
    /// Get confidential resource
    async fn http_get(&mut self, resource_url: String) -> Result<Vec<u8>>;
    /// Attestation and get attestation results token (Base64 endcoded)
    async fn attest(&mut self, host_url: String) -> Result<String>;
}

pub struct KbsProtocolWrapper {
    tee: String,
    tee_key: Option<TeeKey>,
    nonce: String,
    attester: Option<Box<dyn Attester + Send + Sync>>,
    http_client: reqwest::Client,
    authenticated: bool,
}

impl KbsProtocolWrapper {
    pub fn new() -> Result<KbsProtocolWrapper> {
        // Detect TEE type of the current platform.
        let tee_type = detect_tee_type();
        // Create attester instance.
        let attester = tee_type.to_attester().ok();

        Ok(KbsProtocolWrapper {
            tee: tee_type.to_string(),
            tee_key: TeeKey::new().ok(),
            nonce: String::default(),
            attester,
            http_client: build_http_client().unwrap(),
            authenticated: false,
        })
    }

    fn generate_evidence(&self) -> Result<Attestation> {
        let key = self
            .tee_key
            .as_ref()
            .ok_or_else(|| anyhow!("Generate TEE key failed"))?;
        let attester = self
            .attester
            .as_ref()
            .ok_or_else(|| anyhow!("TEE attester missed"))?;

        let tee_pubkey = key
            .export_pubkey()
            .map_err(|e| anyhow!("Export TEE pubkey failed: {:?}", e))?;

        let ehd_chunks = vec![
            self.nonce.clone().into_bytes(),
            tee_pubkey.k_mod.clone().into_bytes(),
            tee_pubkey.k_exp.clone().into_bytes(),
        ];

        let ehd = hash_chunks(ehd_chunks);

        let tee_evidence = attester
            .get_evidence(ehd)
            .map_err(|e| anyhow!("Get TEE evidence failed: {:?}", e))?;

        Ok(Attestation {
            tee_pubkey,
            tee_evidence,
        })
    }

    fn tee(&self) -> &str {
        &self.tee
    }

    fn http_client(&mut self) -> &mut reqwest::Client {
        &mut self.http_client
    }

    async fn attestation(&mut self, kbs_host_url: String) -> Result<String> {
        let challenge = self
            .http_client()
            .post(format!("{kbs_host_url}/{KBS_URL_PREFIX}/auth"))
            .header("Content-Type", "application/json")
            .json(&Request::new(self.tee().to_string()))
            .send()
            .await?
            .json::<Challenge>()
            .await?;
        self.nonce = challenge.nonce.clone();

        let attest_response = self
            .http_client()
            .post(format!("{kbs_host_url}/{KBS_URL_PREFIX}/attest"))
            .header("Content-Type", "application/json")
            .json(&self.generate_evidence()?)
            .send()
            .await?;

        match attest_response.status() {
            reqwest::StatusCode::OK => {
                self.authenticated = true;
                let resp = attest_response.json::<AttestationResponseData>().await?;
                Ok(resp.token)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                let error_info = attest_response.json::<ErrorInformation>().await?;
                bail!("KBS attest unauthorized, Error Info: {:?}", error_info)
            }
            _ => {
                bail!(
                    "KBS Server Internal Failed, Response: {:?}",
                    attest_response.text().await?
                )
            }
        }
    }
}

#[async_trait]
impl KbsRequest for KbsProtocolWrapper {
    async fn http_get(&mut self, url_string: String) -> Result<Vec<u8>> {
        let url = Url::parse(&url_string)
            .map_err(|e| anyhow!("Invalid Request URL {url_string}: {e}"))?;

        // Use default port of KBS: 8080
        let port = url.port().unwrap_or(8080);
        let host_str = url.host_str().ok_or_else(|| anyhow!("No KBS host given"))?;
        let kbs_url = format!("{}://{host_str}:{port}", url.scheme());

        for attempt in 1..=KBS_GET_RESOURCE_MAX_ATTEMPT {
            log::info!("CC-KBC: trying to request KBS, attempt {attempt}");

            if !self.authenticated {
                self.attestation(kbs_url.clone()).await?;
            }

            let res = self.http_client().get(&url_string).send().await?;

            match res.status() {
                reqwest::StatusCode::OK => {
                    let response = res.json::<Response>().await?;
                    let key = self
                        .tee_key
                        .clone()
                        .ok_or_else(|| anyhow!("TEE rsa key missing"))?;
                    let payload_data = response.decrypt_output(key)?;
                    return Ok(payload_data);
                }
                reqwest::StatusCode::UNAUTHORIZED => {
                    self.authenticated = false;
                    continue;
                }
                reqwest::StatusCode::NOT_FOUND => {
                    bail!("KBS resource Not Found (Error 404)")
                }
                _ => {
                    bail!(
                        "KBS Server Internal Failed, Response: {:?}",
                        res.text().await?
                    )
                }
            }
        }

        bail!("Request KBS: Attested but KBS still return Unauthorized")
    }

    async fn attest(&mut self, host_url: String) -> Result<String> {
        self.attestation(host_url).await
    }
}

fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .cookie_store(true)
        .user_agent(format!(
            "attestation-agent-kbs-client/{}",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(Duration::from_secs(KBS_REQ_TIMEOUT_SEC))
        .build()
        .map_err(|e| anyhow!("Build KBS http client failed: {:?}", e))
}
