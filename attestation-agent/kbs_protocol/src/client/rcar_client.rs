// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use kbs_types::{Attestation, Challenge, ErrorInformation, Request, Response};
use log::{debug, warn};
use resource_uri::ResourceUri;
use serde::Deserialize;
use sha2::{Digest, Sha384};

use crate::{
    api::KbsClientCapabilities,
    client::{
        ClientTee, KbsClient, KBS_GET_RESOURCE_MAX_ATTEMPT, KBS_PREFIX, KBS_PROTOCOL_VERSION,
    },
    evidence_provider::EvidenceProvider,
    keypair::TeeKeyPair,
    token_provider::Token,
};

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
                self.rcar_handshake().await?;
            }
        } else {
            self.rcar_handshake().await?;
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
    async fn rcar_handshake(&mut self) -> Result<()> {
        let auth_endpoint = format!("{}/{KBS_PREFIX}/auth", self.kbs_host_url);
        let tee = match &self._tee {
            ClientTee::Unitialized => bail!("tee not initialized"),
            ClientTee::Initializated(tee) => tee.clone(),
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
        let materials = vec![tee_pubkey.k_mod.as_bytes(), tee_pubkey.k_exp.as_bytes()];
        let evidence = self.generate_evidence(challenge.nonce, materials).await?;
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

    async fn generate_evidence(&self, nonce: String, key_materials: Vec<&[u8]>) -> Result<String> {
        let mut hasher = Sha384::new();
        hasher.update(nonce.as_bytes());
        key_materials
            .iter()
            .for_each(|key_material| hasher.update(key_material));

        let ehd = hasher.finalize().to_vec();

        let tee_evidence = self
            .provider
            .get_evidence(ehd)
            .await
            .context("Get TEE evidence failed")?;

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

        if let ClientTee::Unitialized = self._tee {
            let tee = self.provider.get_tee_type().await?;
            self._tee = ClientTee::Initializated(tee);
        }

        for attempt in 1..=KBS_GET_RESOURCE_MAX_ATTEMPT {
            debug!("KBS client: trying to request KBS, attempt {attempt}");

            let res = self.http_client.get(&remote_url).send().await?;

            match res.status() {
                reqwest::StatusCode::OK => {
                    let response = res.json::<Response>().await?;
                    let payload_data = self.tee_key.decrypt_response(response)?;
                    return Ok(payload_data);
                }
                reqwest::StatusCode::UNAUTHORIZED => {
                    warn!(
                        "Authenticating with KBS failed. Perform a new RCAR handshake: {:#?}",
                        res.json::<ErrorInformation>().await?
                    );
                    self.rcar_handshake().await?;

                    continue;
                }
                reqwest::StatusCode::NOT_FOUND => {
                    bail!(
                        "KBS resource Not Found (Error 404): {:#?}",
                        res.json::<ErrorInformation>().await?
                    )
                }
                _ => {
                    bail!(
                        "KBS Server Internal Failed, Response: {:#?}",
                        res.json::<ErrorInformation>().await?
                    )
                }
            }
        }

        bail!("Get resource failed. Unauthorized.")
    }
}

#[cfg(test)]
mod test {
    use std::{env, path::PathBuf};
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
        start_kbs_script.push("test/start_kbs.sh");

        let image = GenericImage::new(
            "ghcr.io/confidential-containers/key-broker-service",
            "built-in-as-v0.7.0",
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
        .with_entrypoint("/usr/local/bin/start_kbs.sh");
        let kbs = docker.run(image);

        let port = kbs.get_host_port_ipv4(8085);
        let kbs_host_url = format!("http://127.0.0.1:{port}");

        env::set_var("AA_SAMPLE_ATTESTER_TEST", "1");
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