// Copyright (c) 2023 Microsoft Corporation
// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::time::Duration;

use anyhow::*;

use crate::{
    client::ClientTee,
    evidence_provider::EvidenceProvider,
    keypair::TeeKeyPair,
    token_provider::{Token, TokenProvider},
};

use super::client::KbsClient;

const KBS_REQ_TIMEOUT_SEC: u64 = 60;

pub struct KbsClientBuilder<T> {
    provider: T,
    kbs_certs: Vec<String>,
    kbs_host_url: String,
    token: Option<String>,
    tee_key: Option<String>,
    initdata: Option<String>,
}

impl KbsClientBuilder<Box<dyn EvidenceProvider>> {
    pub fn with_evidence_provider(
        evidence_provider: Box<dyn EvidenceProvider>,
        kbs_host_url: &str,
    ) -> Self {
        Self {
            provider: evidence_provider,
            kbs_certs: vec![],
            kbs_host_url: kbs_host_url.trim_end_matches('/').to_string(),
            token: None,
            tee_key: None,
            initdata: None,
        }
    }
}

impl KbsClientBuilder<Box<dyn TokenProvider>> {
    pub fn with_token_provider(token_provider: Box<dyn TokenProvider>, kbs_host_url: &str) -> Self {
        Self {
            provider: token_provider,
            kbs_certs: vec![],
            kbs_host_url: kbs_host_url.trim_end_matches('/').to_string(),
            token: None,
            tee_key: None,
            initdata: None,
        }
    }
}

impl<T> KbsClientBuilder<T> {
    pub fn add_kbs_cert(mut self, cert_pem: &str) -> Self {
        self.kbs_certs.push(cert_pem.to_string());
        self
    }

    pub fn set_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self
    }

    pub fn set_tee_key(mut self, tee_key: &str) -> Self {
        self.tee_key = Some(tee_key.to_string());
        self
    }

    pub fn add_initdata(mut self, initdata: String) -> Self {
        self.initdata = Some(initdata);
        self
    }

    pub fn build(self) -> Result<KbsClient<T>> {
        let mut http_client_builder = reqwest::Client::builder()
            .cookie_store(true)
            .user_agent(format!(
                "attestation-agent-kbs-client/{}",
                env!("CARGO_PKG_VERSION")
            ))
            .timeout(Duration::from_secs(KBS_REQ_TIMEOUT_SEC));

        for customer_root_cert in &self.kbs_certs {
            let cert = reqwest::Certificate::from_pem(customer_root_cert.as_bytes())
                .context("read KBS public key cert")?;
            http_client_builder = http_client_builder.add_root_certificate(cert);
        }

        #[cfg(feature = "rust-crypto")]
        {
            http_client_builder = http_client_builder.use_rustls_tls();
        }

        let tee_key = match self.tee_key {
            Some(key) => TeeKeyPair::from_pem(&key[..]).context("read tee public key")?,
            None => TeeKeyPair::new()?,
        };

        let token = match self.token {
            Some(t) => Some(Token::new(t).context("read token")?),
            None => None,
        };

        let client = KbsClient {
            _tee: ClientTee::Uninitialized,
            tee_key,
            token,
            provider: self.provider,
            http_client: http_client_builder
                .build()
                .context("Build KBS http client")?,
            kbs_host_url: self.kbs_host_url,
            _initdata: self.initdata,
        };

        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::{builder::KbsClientBuilder, evidence_provider::MockedEvidenceProvider};

    #[rstest]
    #[tokio::test]
    #[case(
        r"-----BEGIN CERTIFICATE-----
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
    )]
    async fn test_build_client(#[case] cert: &str) {
        KbsClientBuilder::with_evidence_provider(
            Box::<MockedEvidenceProvider>::default(),
            "test.io",
        )
        .add_kbs_cert(cert)
        .build()
        .expect("build client failed");
    }
}
