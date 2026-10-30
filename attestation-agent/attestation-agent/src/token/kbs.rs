// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::config::kbs::KbsConfig;

use anyhow::*;
use kbs_protocol::{KbsClientBuilder, TeeKeyAlgorithm, evidence_provider::NativeEvidenceProvider};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize)]
struct Message {
    token: String,
    tee_keypair: String,
}

#[derive(Default)]
pub struct KbsTokenGetter {
    kbs_host_url: String,
    cert: Option<String>,
    tee_key_algorithm: TeeKeyAlgorithm,
    attestation_policy_selector: String,
}

/// kbs currently accepts no extra parameters. Any key is reported as unsupported.
fn parse_params(params: &HashMap<String, String>) -> Result<()> {
    if let Some(key) = params.keys().next() {
        bail!("{key} parameter is not supported for kbs token");
    }
    Ok(())
}

impl KbsTokenGetter {
    pub async fn get_token(
        &self,
        initdata: Option<&str>,
        params: &HashMap<String, String>,
    ) -> Result<Vec<u8>> {
        parse_params(params)?;

        let evidence_provider = Box::new(NativeEvidenceProvider::new()?);

        let mut builder =
            KbsClientBuilder::with_evidence_provider(evidence_provider, &self.kbs_host_url);

        if let Some(cert) = &self.cert {
            builder = builder.add_kbs_cert(cert);
        }
        builder = builder.set_tee_key_algorithm(self.tee_key_algorithm);

        if !self.attestation_policy_selector.is_empty() {
            builder = builder.set_attestation_policy_selector(&self.attestation_policy_selector);
        }

        if let Some(initdata) = initdata {
            builder = builder.add_initdata(initdata.to_string());
        }

        let mut client = builder.build()?;

        let (token, tee_keypair) = client.get_token().await?;
        let message = Message {
            token: token.content,
            tee_keypair: tee_keypair.to_pem()?.to_string(),
        };

        let res = serde_json::to_vec(&message)?;
        Ok(res)
    }
}

impl KbsTokenGetter {
    pub fn new(config: &KbsConfig) -> Self {
        Self {
            kbs_host_url: config.url.clone(),
            cert: config.cert.clone(),
            tee_key_algorithm: config.tee_key_algorithm,
            attestation_policy_selector: config.attestation_policy_selector.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn any_parameter_is_rejected() {
        let getter = KbsTokenGetter::default();
        let mut params = HashMap::new();
        params.insert("nonce".to_string(), "value".to_string());
        let err = getter
            .get_token(None, &params)
            .await
            .expect_err("kbs must reject parameters");
        assert_eq!(
            err.to_string(),
            "nonce parameter is not supported for kbs token"
        );
    }
}
