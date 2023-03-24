// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{
    common::crypto::decrypt,
    kbc_modules::{KbcCheckInfo, KbcInterface},
};

mod attester;
mod crypto;
mod kbs_protocol;

use anyhow::*;
use async_trait::async_trait;
use attester::{detect_tee_type, Attester};
use core::time::Duration;
use crypto::{hash_chunks, TeeKey};
use kbs_protocol::message::*;
use kbs_types::ErrorInformation;
use url::Url;
use zeroize::Zeroizing;

use super::{uri::ResourceUri, AnnotationPacket};

const KBS_REQ_TIMEOUT_SEC: u64 = 60;
const KBS_GET_RESOURCE_MAX_ATTEMPT: u64 = 3;

pub const KBS_URL_PREFIX: &str = "kbs/v0";

pub struct Kbc {
    tee: String,
    kbs_uri: Url,
    token: Option<String>,
    nonce: String,
    tee_key: Option<TeeKey>,
    attester: Option<Box<dyn Attester + Send + Sync>>,
    http_client: reqwest::Client,
    authenticated: bool,
}

#[async_trait]
impl KbcInterface for Kbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Err(anyhow!("Check API of this KBC is unimplemented."))
    }

    async fn decrypt_payload(&mut self, annotation_packet: AnnotationPacket) -> Result<Vec<u8>> {
        let key_url = self.resource_to_kbs_uri(&annotation_packet.kid)?;

        let response = self.request_kbs_resource(key_url).await?;
        let key = Zeroizing::new(self.decrypt_response_output(response)?);

        decrypt(
            key,
            base64::decode(annotation_packet.wrapped_data)?,
            base64::decode(annotation_packet.iv)?,
            &annotation_packet.wrap_type,
        )
    }

    #[allow(unused_assignments)]
    async fn get_resource(&mut self, desc: ResourceUri) -> Result<Vec<u8>> {
        let resource_url = self.resource_to_kbs_uri(&desc)?;
        let response = self.request_kbs_resource(resource_url).await?;

        self.decrypt_response_output(response)
    }
}

impl Kbc {
    pub fn new(kbs_uri: String) -> Result<Kbc> {
        // Check the KBS URI validity
        let url = Url::parse(&kbs_uri).map_err(|e| anyhow!("Invalid URI {kbs_uri}: {e}"))?;
        if !url.has_host() {
            bail!("{kbs_uri} is missing a host");
        }

        // Detect TEE type of the current platform.
        let tee_type = detect_tee_type();

        // Create attester instance.
        let attester = tee_type.to_attester().ok();

        Ok(Kbc {
            tee: tee_type.to_string(),
            kbs_uri: url,
            token: None,
            nonce: String::default(),
            tee_key: TeeKey::new().ok(),
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
            tee_pubkey.k.clone().into_bytes(),
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

    fn decrypt_response_output(&self, response: Response) -> Result<Vec<u8>> {
        let key = self
            .tee_key
            .clone()
            .ok_or_else(|| anyhow!("TEE rsa key missing"))?;
        response.decrypt_output(key)
    }

    fn tee(&self) -> &str {
        &self.tee
    }

    fn kbs_uri(&self) -> &str {
        self.kbs_uri.as_str()
    }

    fn http_client(&mut self) -> &mut reqwest::Client {
        &mut self.http_client
    }

    async fn establish_kbs_session(&mut self) -> Result<()> {
        let kbs_uri = self.kbs_uri().to_string();

        let challenge = self
            .http_client()
            .post(format!("{kbs_uri}{KBS_URL_PREFIX}/auth"))
            .header("Content-Type", "application/json")
            .json(&Request::new(self.tee().to_string()))
            .send()
            .await?
            .json::<Challenge>()
            .await?;
        self.nonce = challenge.nonce.clone();

        let attest_response = self
            .http_client()
            .post(format!("{kbs_uri}{KBS_URL_PREFIX}/attest"))
            .header("Content-Type", "application/json")
            .json(&self.generate_evidence()?)
            .send()
            .await?;

        match attest_response.status() {
            reqwest::StatusCode::OK => {
                self.authenticated = true;
                Ok(())
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

    async fn request_kbs_resource(&mut self, resource_url: String) -> Result<Response> {
        for attempt in 1..=KBS_GET_RESOURCE_MAX_ATTEMPT {
            log::info!("CC-KBC: trying to get resource, attempt {attempt}");

            if !self.authenticated {
                self.establish_kbs_session().await?;
            }

            let res = self.http_client().get(&resource_url).send().await?;

            match res.status() {
                reqwest::StatusCode::OK => {
                    let response = res.json::<Response>().await?;
                    return Ok(response);
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

        bail!("Request KBS resource: Attested but KBS still return Unauthorized")
    }

    /// Convert a [`ResourceUri`] to a KBS URL.
    pub fn resource_to_kbs_uri(&self, resource: &ResourceUri) -> Result<String> {
        let kbs_host = self
            .kbs_uri
            .host_str()
            .ok_or_else(|| anyhow!("Invalid URL: {}", self.kbs_uri))?;

        let kbs_addr = if let Some(port) = self.kbs_uri.port() {
            format!("{kbs_host}:{port}")
        } else {
            kbs_host.to_string()
        };

        if !resource.kbs_addr.is_empty() && resource.kbs_addr != kbs_addr {
            bail!(
                "The resource KBS host {} differs from the KBS URL one {kbs_addr}",
                resource.kbs_addr
            );
        }

        let kbs_addr = &self.kbs_uri();
        let repo = &resource.repository;
        let r#type = &resource.r#type;
        let tag = &resource.tag;
        Ok(format!(
            "{kbs_addr}{KBS_URL_PREFIX}/resource/{repo}/{type}/{tag}"
        ))
    }
}

fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .cookie_store(true)
        .user_agent(format!(
            "attestation-agent-cc-kbc/{}",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(Duration::from_secs(KBS_REQ_TIMEOUT_SEC))
        .build()
        .map_err(|e| anyhow!("Build KBS http client failed: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::ResourceUri;
    use crate::kbc_modules::cc_kbc::Kbc;

    const RESOURCE_URL_PORT: &str = "kbs://127.0.0.1:8081/alice/cosign-key/213";
    const RESOURCE_URL_NO_PORT: &str = "kbs://127.0.0.1/alice/cosign-key/213";
    const RESOURCE_NO_HOST_URL: &str = "kbs:///alice/cosign-key/213";

    const KBS_URL_PORT: &str = "https://127.0.0.1:8081";
    const KBS_URL_NO_PORT: &str = "https://127.0.0.1";
    const KBS_INVALID_URL: &str = "kbs:///alice/cosign-key/213";

    const RESOURCE_KBS_URL_PORT: &str =
        "https://127.0.0.1:8081/kbs/v0/resource/alice/cosign-key/213";
    const RESOURCE_KBS_URL_NO_PORT: &str = "https://127.0.0.1/kbs/v0/resource/alice/cosign-key/213";

    #[test]
    fn new_invalid_uri() {
        let kbc = Kbc::new(KBS_INVALID_URL.to_string());
        assert!(kbc.is_err());
    }

    #[test]
    fn new_valid_uri() {
        let kbc = Kbc::new(KBS_URL_PORT.to_string());
        assert!(kbc.is_ok());
    }

    fn to_kbs_uri(kbs_url: &str, resource_url: &str, expected_kbs_url: &str) {
        let resource: ResourceUri =
            serde_json::from_str(&format!("\"{resource_url}\"")).expect("deserialize failed");

        let kbc = Kbc::new(kbs_url.to_string());
        assert!(kbc.is_ok());

        println!(
            "{} {:?}",
            resource.kbs_addr,
            kbc.as_ref().unwrap().kbs_uri()
        );
        let resource_kbs_url = kbc.unwrap().resource_to_kbs_uri(&resource);

        assert!(resource_kbs_url.is_ok());
        assert_eq!(resource_kbs_url.unwrap(), expected_kbs_url);
    }

    #[test]
    fn resource_port_to_kbs_uri() {
        to_kbs_uri(KBS_URL_PORT, RESOURCE_URL_PORT, RESOURCE_KBS_URL_PORT);
    }

    #[test]
    fn resource_no_port_to_kbs_uri() {
        to_kbs_uri(
            KBS_URL_NO_PORT,
            RESOURCE_URL_NO_PORT,
            RESOURCE_KBS_URL_NO_PORT,
        );
    }

    #[test]
    fn resource_no_host_to_kbs_uri() {
        to_kbs_uri(KBS_URL_PORT, RESOURCE_NO_HOST_URL, RESOURCE_KBS_URL_PORT);
    }
}
