// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::config::coco_as::CoCoASConfig;

use anyhow::*;
use attester::{BoxedAttester, detect_tee_type};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use std::collections::HashMap;
use tracing::warn;

#[derive(Default)]
pub struct CoCoASTokenGetter {
    as_uri: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    nonce: Option<String>,
}

impl Parameters {
    pub fn from_params(params: &HashMap<String, String>) -> Result<Self> {
        let parameters = serde_json::from_value(serde_json::to_value(params)?)?;
        Ok(parameters)
    }
}

impl CoCoASTokenGetter {
    pub async fn get_token(&self, params: &HashMap<String, String>) -> Result<Vec<u8>> {
        let parameters = Parameters::from_params(params)?;
        let challenge = match parameters.nonce {
            Some(nonce) => URL_SAFE_NO_PAD
                .decode(nonce)
                .context("invalid base64 URL-safe nonce")?,
            None => {
                warn!("no nonce provided for coco_as token, using empty challenge");
                Vec::new()
            }
        };
        let primary_tee = detect_tee_type();
        let attester = BoxedAttester::try_from(primary_tee)?;
        let evidence = attester.get_evidence(challenge).await?;

        let tee_string = serde_json::to_string(&primary_tee)?
            .trim_end_matches('"')
            .trim_start_matches('"')
            .to_string();

        let request_body = serde_json::json!({
            "verification_requests": [{
                "tee": tee_string,
                "evidence": URL_SAFE_NO_PAD.encode(serde_json::to_string(&evidence)?.as_bytes()),
            }],
            "policy_ids": [],
        });

        let client = reqwest::Client::new();
        let attest_endpoint = format!("{}/attestation", self.as_uri);
        let res = client
            .post(attest_endpoint)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        match res.status() {
            reqwest::StatusCode::OK => {
                let token = res.text().await?;
                Ok(token.as_bytes().to_vec())
            }
            _ => {
                bail!(
                    "Remote Attestation Failed, AS Response: {:?}",
                    res.text().await?
                );
            }
        }
    }
}

impl CoCoASTokenGetter {
    pub fn new(config: &CoCoASConfig) -> Self {
        Self {
            as_uri: config.url.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::collections::HashMap;

    fn params(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    #[rstest]
    #[case(&[] as &[(&str, &str)], true, None)]
    #[case(&[("nonce", "Y2hhbGxlbmdl")], true, Some("Y2hhbGxlbmdl"))]
    #[case(&[("nonce", "")], true, Some(""))]
    #[case(&[("foo", "bar")], false, None)]
    #[case(&[("nonce", "Y2hhbGxlbmdl"), ("foo", "bar")], false, None)]
    fn from_params(
        #[case] entries: &[(&str, &str)],
        #[case] expect_ok: bool,
        #[case] nonce: Option<&str>,
    ) {
        let result = Parameters::from_params(&params(entries));
        if expect_ok {
            assert_eq!(result.expect("params").nonce.as_deref(), nonce);
        } else {
            assert!(result.is_err());
        }
    }
}
