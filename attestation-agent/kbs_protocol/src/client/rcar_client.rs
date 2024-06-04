// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::time::Duration;

use anyhow::{bail, Context};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use kbs_types::{Attestation, Challenge, ErrorInformation, Request, Response, Tee};
use log::{debug, warn};
use resource_uri::ResourceUri;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha384};

use crate::{
    api::KbsClientCapabilities,
    client::{
        ClientTee, KbsClient, KBS_GET_RESOURCE_MAX_ATTEMPT, KBS_PREFIX, KBS_PROTOCOL_VERSION,
    },
    evidence_provider::EvidenceProvider,
    keypair::TeeKeyPair,
    token_provider::Token,
    Error, Result,
};

/// When executing get token, RCAR handshake should retry if failed to
/// make the logic robust. This constant is the max retry times.
const RCAR_MAX_ATTEMPT: i32 = 5;

/// The interval (seconds) between RCAR handshake retries.
const RCAR_RETRY_TIMEOUT_SECOND: u64 = 1;

#[derive(Deserialize, Debug, Clone)]
struct AttestationResponseData {
    // Attestation token in JWT format
    token: String,
}

impl KbsClient<Box<dyn EvidenceProvider>> {
    /// Get a [`TeeKeyPair`] and a [`Token`] that certifies the [`TeeKeyPair`].
    /// It will check if the client already has a valid token. If so, return
    /// the token. If not, the client will generate a new key pair and do a new
    /// RCAR handshaking.
    pub async fn get_token(&mut self) -> Result<(Token, TeeKeyPair)> {
        if let Some(token) = &self.token {
            if token.check_valid().is_err() {
                let mut retry_times = 1;
                loop {
                    let res = self
                        .rcar_handshake()
                        .await
                        .map_err(|e| Error::RcarHandshake(e.to_string()));
                    match res {
                        Ok(_) => break,
                        Err(e) => {
                            if retry_times >= RCAR_MAX_ATTEMPT {
                                return Err(Error::RcarHandshake(format!("Get token failed because of RCAR handshake retried {RCAR_MAX_ATTEMPT} times.")));
                            } else {
                                warn!("RCAR handshake failed: {e}, retry {retry_times}...");
                                retry_times += 1;
                                tokio::time::sleep(Duration::from_secs(RCAR_RETRY_TIMEOUT_SECOND))
                                    .await;
                            }
                        }
                    }
                }
            }
        } else {
            let mut retry_times = 1;
            loop {
                let res = self
                    .rcar_handshake()
                    .await
                    .map_err(|e| Error::RcarHandshake(e.to_string()));
                match res {
                    Ok(_) => break,
                    Err(e) => {
                        if retry_times >= RCAR_MAX_ATTEMPT {
                            return Err(Error::RcarHandshake(format!("Get token failed because of RCAR handshake retried {RCAR_MAX_ATTEMPT} times.")));
                        } else {
                            warn!("RCAR handshake failed: {e}, retry {retry_times}...");
                            retry_times += 1;
                            tokio::time::sleep(Duration::from_secs(RCAR_RETRY_TIMEOUT_SECOND))
                                .await;
                        }
                    }
                }
            }
        }

        assert!(self.token.is_some());

        let token = self.token.clone().unwrap();
        let tee_key = self.tee_key.clone();
        Ok((token, tee_key))
    }

    /// Perform RCAR handshake with the given kbs host. If succeeds, the client will
    /// store the token.
    ///
    /// Note: if RCAR succeeds, the http client will record the cookie with the kbs server,
    /// which means that this client can be then used to retrieve resources.
    async fn rcar_handshake(&mut self) -> anyhow::Result<()> {
        let auth_endpoint = format!("{}/{KBS_PREFIX}/auth", self.kbs_host_url);

        let tee = match &self._tee {
            ClientTee::Unitialized => {
                let tee = self.provider.get_tee_type().await?;
                self._tee = ClientTee::_Initializated(tee);
                tee
            }
            ClientTee::_Initializated(tee) => *tee,
        };

        let request = Request {
            version: String::from(KBS_PROTOCOL_VERSION),
            tee,
            extra_params: String::new(),
        };

        debug!("send auth request to {auth_endpoint}");

        let challenge = self
            .http_client
            .post(auth_endpoint)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?
            .json::<Challenge>()
            .await?;

        debug!("get challenge: {challenge:#?}");
        let tee_pubkey = self.tee_key.export_pubkey()?;
        let runtime_data = json!({
            "tee-pubkey": tee_pubkey,
            "nonce": challenge.nonce,
        });
        let runtime_data =
            serde_json::to_string(&runtime_data).context("serialize runtime data failed")?;
        let evidence = self
            .generate_evidence(tee, runtime_data, challenge.nonce)
            .await?;
        debug!("get evidence with challenge: {evidence}");

        let attest_endpoint = format!("{}/{KBS_PREFIX}/attest", self.kbs_host_url);
        let attest = Attestation {
            tee_pubkey,
            tee_evidence: evidence,
        };

        debug!("send attest request.");
        let attest_response = self
            .http_client
            .post(attest_endpoint)
            .header("Content-Type", "application/json")
            .json(&attest)
            .send()
            .await?;

        match attest_response.status() {
            reqwest::StatusCode::OK => {
                let resp = attest_response.json::<AttestationResponseData>().await?;
                let token = Token::new(resp.token)?;
                self.token = Some(token);
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                let error_info = attest_response.json::<ErrorInformation>().await?;
                bail!("KBS attest unauthorized, Error Info: {:?}", error_info);
            }
            _ => {
                bail!(
                    "KBS Server Internal Failed, Response: {:?}",
                    attest_response.text().await?
                );
            }
        }

        Ok(())
    }

    async fn generate_evidence(
        &self,
        tee: Tee,
        runtime_data: String,
        nonce: String,
    ) -> Result<String> {
        debug!("Challenge nonce: {nonce}");
        let mut hasher = Sha384::new();
        hasher.update(runtime_data);

        let ehd = match tee {
            // IBM SE uses nonce as runtime_data to pass attestation_request
            Tee::Se => STANDARD
                .decode(nonce)
                .map_err(|e| Error::GetEvidence(e.to_string()))?,
            _ => hasher.finalize().to_vec(),
        };

        let tee_evidence = self
            .provider
            .get_evidence(ehd)
            .await
            .context("Get TEE evidence failed")
            .map_err(|e| Error::GetEvidence(e.to_string()))?;

        Ok(tee_evidence)
    }
}

#[async_trait]
impl KbsClientCapabilities for KbsClient<Box<dyn EvidenceProvider>> {
    async fn get_resource(&mut self, resource_uri: ResourceUri) -> Result<Vec<u8>> {
        let remote_url = format!(
            "{}/{KBS_PREFIX}/resource/{}/{}/{}",
            self.kbs_host_url, resource_uri.repository, resource_uri.r#type, resource_uri.tag
        );

        for attempt in 1..=KBS_GET_RESOURCE_MAX_ATTEMPT {
            debug!("KBS client: trying to request KBS, attempt {attempt}");

            let res = self
                .http_client
                .get(&remote_url)
                .send()
                .await
                .map_err(|e| Error::HttpError(format!("get failed: {e}")))?;

            match res.status() {
                reqwest::StatusCode::OK => {
                    let response = res
                        .json::<Response>()
                        .await
                        .map_err(|e| Error::KbsResponseDeserializationFailed(e.to_string()))?;
                    let payload_data = self
                        .tee_key
                        .decrypt_response(response)
                        .map_err(|e| Error::DecryptResponseFailed(e.to_string()))?;
                    return Ok(payload_data);
                }
                reqwest::StatusCode::UNAUTHORIZED => {
                    warn!(
                        "Authenticating with KBS failed. Perform a new RCAR handshake: {:#?}",
                        res.json::<ErrorInformation>()
                            .await
                            .map_err(|e| Error::KbsResponseDeserializationFailed(e.to_string()))?,
                    );
                    self.rcar_handshake()
                        .await
                        .map_err(|e| Error::RcarHandshake(e.to_string()))?;

                    continue;
                }
                reqwest::StatusCode::NOT_FOUND => {
                    let errorinfo = format!(
                        "KBS resource Not Found (Error 404): {:#?}",
                        res.json::<ErrorInformation>()
                            .await
                            .map_err(|e| Error::KbsResponseDeserializationFailed(e.to_string()))?
                    );

                    return Err(Error::ResourceNotFound(errorinfo));
                }
                _ => {
                    let errorinfo = format!(
                        "KBS Server Internal Failed, Response: {:#?}",
                        res.json::<ErrorInformation>()
                            .await
                            .map_err(|e| Error::KbsResponseDeserializationFailed(e.to_string()))?
                    );

                    return Err(Error::KbsInternalError(errorinfo));
                }
            }
        }

        Err(Error::UnAuthorized)
    }
}

#[cfg(test)]
mod test {
    use std::{env, path::PathBuf, time::Duration};
    use testcontainers::{clients, images::generic::GenericImage};
    use tokio::fs;

    use crate::{
        evidence_provider::NativeEvidenceProvider, KbsClientBuilder, KbsClientCapabilities,
    };

    const CONTENT: &[u8] = b"test content";

    #[tokio::test]
    #[serial_test::serial]
    async fn test_client() {
        // prepare test resource
        let tmp = tempfile::tempdir().expect("create tempdir");
        let mut resource_path = PathBuf::new();
        resource_path.push(tmp.path());
        resource_path.push("default/key");
        fs::create_dir_all(resource_path.clone())
            .await
            .expect("create resource path");

        resource_path.push("testfile");
        fs::write(resource_path.clone(), CONTENT)
            .await
            .expect("write content");

        // launch kbs
        let docker = clients::Cli::default();

        // we should change the entrypoint of the kbs image by using
        // a start script
        let mut start_kbs_script = env::current_dir().expect("get cwd");
        let mut kbs_config = start_kbs_script.clone();
        let mut policy = start_kbs_script.clone();
        start_kbs_script.push("test/start_kbs.sh");
        kbs_config.push("test/kbs-config.toml");
        policy.push("test/policy.rego");

        let image = GenericImage::new(
            "ghcr.io/confidential-containers/staged-images/kbs",
            "latest",
        )
        .with_exposed_port(8085)
        .with_volume(
            tmp.path().as_os_str().to_string_lossy(),
            "/opt/confidential-containers/kbs/repository",
        )
        .with_volume(
            start_kbs_script.into_os_string().to_string_lossy(),
            "/usr/local/bin/start_kbs.sh",
        )
        .with_volume(
            kbs_config.into_os_string().to_string_lossy(),
            "/etc/kbs-config.toml",
        )
        .with_volume(
            policy.into_os_string().to_string_lossy(),
            "/opa/confidential-containers/kbs/policy.rego",
        )
        .with_entrypoint("/usr/local/bin/start_kbs.sh");
        let kbs = docker.run(image);

        tokio::time::sleep(Duration::from_secs(10)).await;
        let port = kbs.get_host_port_ipv4(8085);
        let kbs_host_url = format!("http://127.0.0.1:{port}");

        let evidence_provider = Box::new(NativeEvidenceProvider::new().unwrap());
        let mut client = KbsClientBuilder::with_evidence_provider(evidence_provider, &kbs_host_url)
            .build()
            .expect("client create");
        let resource_uri = "kbs:///default/key/testfile"
            .try_into()
            .expect("resource uri");

        let resource = client
            .get_resource(resource_uri)
            .await
            .expect("get resource");
        assert_eq!(resource, CONTENT);

        let (token, key) = client.get_token().await.expect("get token");
        println!("Get token : {token:?}");
        println!("Get key: {key:?}");
    }
}
