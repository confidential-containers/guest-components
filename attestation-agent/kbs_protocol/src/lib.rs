// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use async_trait::async_trait;
use attester::{detect_tee_type, Attester, Tee};
use core::time::Duration;
use crypto::{hash_chunks, pkcs1_pem_to_teepubkey, TeeKey};
use kbs_types::{Attestation, ErrorInformation, TeePubKey};
use std::convert::TryFrom;
use types::*;
use url::Url;

pub mod types;

const KBS_REQ_TIMEOUT_SEC: u64 = 60;
const KBS_GET_RESOURCE_MAX_ATTEMPT: u64 = 3;

pub const KBS_PREFIX: &str = "/kbs/v0";

#[async_trait]
pub trait KbsRequest {
    /// Get confidential resource
    async fn http_get(&mut self, resource_url: String) -> Result<Vec<u8>>;
    /// Attestation and get attestation results token (Base64 endcoded)
    async fn attest(&mut self, url: String, tee_pubkey_pem: Option<String>) -> Result<String>;
}

type BoxedAttester = Box<dyn Attester + Send + Sync>;

pub struct KbsProtocolWrapper {
    tee: String,
    tee_key: TeeKey,
    nonce: Option<String>,
    attester: Option<BoxedAttester>,
    http_client: reqwest::Client,
    authenticated: bool,
}

pub struct NoTee;
pub struct NoAttester;

pub struct KbsProtocolWrapperBuilder<T, A> {
    tee: T,
    attester: A,
    kbs_certs: Vec<String>,
}
type WrapperBuilder<T, A> = KbsProtocolWrapperBuilder<T, A>;

impl<T, A> WrapperBuilder<T, A> {
    pub fn add_kbs_cert(mut self, cert_pem: String) -> Self {
        self.kbs_certs.push(cert_pem);
        self
    }
}

impl WrapperBuilder<NoTee, NoAttester> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            tee: NoTee,
            attester: NoAttester,
            kbs_certs: vec![],
        }
    }

    pub fn with_tee(self, tee: Tee) -> WrapperBuilder<Tee, NoAttester> {
        WrapperBuilder {
            tee,
            attester: self.attester,
            kbs_certs: self.kbs_certs,
        }
    }
}

impl WrapperBuilder<Tee, NoAttester> {
    pub fn with_attester(self, attester: BoxedAttester) -> WrapperBuilder<Tee, BoxedAttester> {
        WrapperBuilder {
            tee: self.tee,
            attester,
            kbs_certs: self.kbs_certs,
        }
    }
}

impl WrapperBuilder<Tee, NoAttester> {
    pub fn build(self) -> Result<KbsProtocolWrapper> {
        let attester = self.tee.to_attester()?;
        let wrapper = WrapperBuilder::new()
            .with_tee(self.tee)
            .with_attester(attester)
            .build()?;
        Ok(wrapper)
    }
}

impl WrapperBuilder<Tee, BoxedAttester> {
    pub fn build(self) -> Result<KbsProtocolWrapper> {
        self.try_into()
    }
}

impl TryFrom<WrapperBuilder<Tee, BoxedAttester>> for KbsProtocolWrapper {
    type Error = Error;
    fn try_from(builder: WrapperBuilder<Tee, BoxedAttester>) -> Result<Self> {
        let mut wrapper = Self::new(builder.kbs_certs)?;
        wrapper.tee = builder.tee.to_string();
        wrapper.attester = Some(builder.attester);
        Ok(wrapper)
    }
}

impl KbsProtocolWrapper {
    pub fn new(kbs_root_certs_pem: Vec<String>) -> Result<KbsProtocolWrapper> {
        let tee_key = TeeKey::new().map_err(|e| anyhow!("Generate TEE key failed: {e}"))?;
        // Detect TEE type of the current platform.
        let tee_type = detect_tee_type();
        // Create attester instance.
        let attester = tee_type.to_attester().ok();

        Ok(KbsProtocolWrapper {
            tee: tee_type.to_string(),
            attester,
            tee_key,
            nonce: None,
            http_client: build_http_client(kbs_root_certs_pem)?,
            authenticated: false,
        })
    }

    fn generate_evidence(&self, tee_pubkey: TeePubKey) -> Result<Attestation> {
        let nonce = self
            .nonce
            .to_owned()
            .ok_or_else(|| anyhow!("Nonce is not set"))?;

        let ehd_chunks = vec![
            nonce.into_bytes(),
            tee_pubkey.k_mod.clone().into_bytes(),
            tee_pubkey.k_exp.clone().into_bytes(),
        ];

        let ehd = hash_chunks(ehd_chunks);

        let attester = self
            .attester
            .as_ref()
            .ok_or_else(|| anyhow!("Attester is not set"))?;

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

    async fn attestation(
        &mut self,
        kbs_root_url: String,
        tee_pubkey_pem: Option<String>,
    ) -> Result<String> {
        let challenge = self
            .http_client()
            .post(format!("{kbs_root_url}{KBS_PREFIX}/auth"))
            .header("Content-Type", "application/json")
            .json(&Request::new(self.tee().to_string()))
            .send()
            .await?
            .json::<Challenge>()
            .await?;
        self.nonce = Some(challenge.nonce.clone());

        let pubkey = match tee_pubkey_pem {
            Some(k) => pkcs1_pem_to_teepubkey(k)?,
            None => {
                let key = TeeKey::new()?;
                let key_exp = key
                    .export_pubkey()
                    .map_err(|e| anyhow!("Export TEE pubkey failed: {:?}", e))?;
                self.tee_key = key;
                key_exp
            }
        };

        let attest_response = self
            .http_client()
            .post(format!("{kbs_root_url}{KBS_PREFIX}/attest"))
            .header("Content-Type", "application/json")
            .json(&self.generate_evidence(pubkey)?)
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
        let _ = Url::parse(&url_string)
            .map_err(|e| anyhow!("Invalid Request URL {url_string}: {e}"))?;

        let root_url = url_string.split(KBS_PREFIX).collect::<Vec<&str>>()[0].to_string();

        for attempt in 1..=KBS_GET_RESOURCE_MAX_ATTEMPT {
            log::info!("CC-KBC: trying to request KBS, attempt {attempt}");

            if !self.authenticated {
                self.attestation(root_url.clone(), None).await?;
            }

            let res = self.http_client().get(&url_string).send().await?;

            match res.status() {
                reqwest::StatusCode::OK => {
                    let response = res.json::<Response>().await?;
                    let payload_data = response.decrypt_output(&self.tee_key)?;
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

    async fn attest(&mut self, url: String, tee_pubkey_pem: Option<String>) -> Result<String> {
        self.attestation(url, tee_pubkey_pem).await
    }
}

fn build_http_client(kbs_root_certs_pem: Vec<String>) -> Result<reqwest::Client> {
    let mut client_builder = reqwest::Client::builder()
        .cookie_store(true)
        .user_agent(format!(
            "attestation-agent-kbs-client/{}",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(Duration::from_secs(KBS_REQ_TIMEOUT_SEC));

    for custom_root_cert in kbs_root_certs_pem.iter() {
        let cert = reqwest::Certificate::from_pem(custom_root_cert.as_bytes())?;
        client_builder = client_builder.add_root_certificate(cert);
    }

    client_builder
        .build()
        .map_err(|e| anyhow!("Build KBS http client failed: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_http_client() {
        let test_certs = vec!["-----BEGIN CERTIFICATE-----
MIIBzTCCAX+gAwIBAgIUOGdGRmt/IDSVIem7iFwsuxnV62AwBQYDK2VwMGkxCzAJ
BgNVBAYTAkNOMREwDwYDVQQIDAhTaGFuZ2hhaTERMA8GA1UEBwwIU2hhbmdoYWkx
EDAOBgNVBAoMB0FsaWJhYmExDzANBgNVBAsMBkFsaXl1bjERMA8GA1UEAwwIS0JT
LXJvb3QwHhcNMjMwNzE0MDYzMzA1WhcNMjMwODEzMDYzMzA1WjBpMQswCQYDVQQG
EwJDTjERMA8GA1UECAwIU2hhbmdoYWkxETAPBgNVBAcMCFNoYW5naGFpMRAwDgYD
VQQKDAdBbGliYWJhMQ8wDQYDVQQLDAZBbGl5dW4xETAPBgNVBAMMCEtCUy1yb290
MCowBQYDK2VwAyEAOo8z6/Ul3XvNBf2Oa7qDevljyhGSKyGMjV+4qneVNr+jOTA3
MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgXgMB0GA1UdDgQWBBREKNLFRe7fCBKRffTv
x13TMfDeczAFBgMrZXADQQBpP6ABBkzVj3mF55nWUtP5vxwq3t91wqQJ6NyC7WsT
3Z29bFfJn7C280JfkCqiqeSZjYV/JjTepATH659kktcA
-----END CERTIFICATE-----"
            .to_string()];
        assert!(build_http_client(test_certs).is_ok());
    }
}
