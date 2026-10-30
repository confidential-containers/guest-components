// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::config::coco_as::CoCoASConfig;

use anyhow::*;
use attester::{BoxedAttester, detect_tee_type};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use kbs_types::HashAlgorithm;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use tracing::warn;

/// CoCo AS hashes structured runtime data with SHA-384 when the request omits
/// `runtime_data_hash_algorithm`.
const RUNTIME_DATA_HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha384;

/// Parse `runtime_data`, then bind evidence to the same digest CoCo AS checks:
/// SHA-384 over JSON Canonicalization Scheme (RFC 8785) bytes.
fn runtime_data_binding(runtime_data: &str) -> Result<(Vec<u8>, Value)> {
    let parsed: Value = serde_json::from_str(runtime_data).context("runtime_data must be JSON")?;
    let canonical =
        serde_json_canonicalizer::to_vec(&parsed).context("canonicalize runtime_data")?;
    let challenge = RUNTIME_DATA_HASH_ALGORITHM.digest(&canonical);
    Ok((challenge, parsed))
}

#[derive(Default)]
pub struct CoCoASTokenGetter {
    as_uri: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    nonce: Option<String>,
    runtime_data: Option<String>,
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
        let (challenge, runtime_data) = match (parameters.nonce, parameters.runtime_data) {
            (Some(_), Some(_)) => {
                bail!("only one of nonce and runtime_data may be set")
            }
            (Some(nonce), None) => (
                URL_SAFE_NO_PAD
                    .decode(nonce)
                    .context("invalid base64 URL-safe nonce")?,
                None,
            ),
            (None, Some(runtime_data)) => {
                let (challenge, parsed) = runtime_data_binding(&runtime_data)?;
                (challenge, Some(parsed))
            }
            (None, None) => {
                warn!("no nonce or runtime_data provided for coco_as token, using empty challenge");
                (Vec::new(), None)
            }
        };
        let primary_tee = detect_tee_type();
        let attester = BoxedAttester::try_from(primary_tee)?;
        let evidence = attester.get_evidence(challenge).await?;

        let tee_string = serde_json::to_string(&primary_tee)?
            .trim_end_matches('"')
            .trim_start_matches('"')
            .to_string();

        let mut request_body = serde_json::json!({
            "verification_requests": [{
                "tee": tee_string,
                "evidence": URL_SAFE_NO_PAD.encode(serde_json::to_string(&evidence)?.as_bytes()),
            }],
            "policy_ids": [],
        });
        if let Some(runtime_data) = runtime_data {
            // `structured` is canonicalized and hashed by CoCo AS before it is
            // compared with report data. The challenge above is that digest.
            request_body["verification_requests"][0]["runtime_data"] =
                serde_json::json!({ "structured": runtime_data });
            request_body["verification_requests"][0]["runtime_data_hash_algorithm"] =
                serde_json::json!("sha384");
        }

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
    #[case(&[] as &[(&str, &str)], true, None, None)]
    #[case(&[("nonce", "Y2hhbGxlbmdl")], true, Some("Y2hhbGxlbmdl"), None)]
    #[case(&[("nonce", "")], true, Some(""), None)]
    #[case(&[("runtime_data", "{\"k\":1}")], true, None, Some("{\"k\":1}"))]
    #[case(&[("nonce", "abc"), ("runtime_data", "{}")], true, Some("abc"), Some("{}"))]
    #[case(&[("foo", "bar")], false, None, None)]
    #[case(&[("nonce", "Y2hhbGxlbmdl"), ("foo", "bar")], false, None, None)]
    fn from_params(
        #[case] entries: &[(&str, &str)],
        #[case] expect_ok: bool,
        #[case] nonce: Option<&str>,
        #[case] runtime_data: Option<&str>,
    ) {
        let result = Parameters::from_params(&params(entries));
        if expect_ok {
            let parsed = result.expect("params");
            assert_eq!(parsed.nonce.as_deref(), nonce);
            assert_eq!(parsed.runtime_data.as_deref(), runtime_data);
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn runtime_data_challenge_matches_coco_as_structured_binding() {
        // Key order differs. CoCo AS canonicalizes before SHA-384, and this
        // digest is the vector from its structured runtime-data test.
        let (reordered, _) = runtime_data_binding(r#"{"b":1,"a":"test","c":{"d":"e"}}"#).unwrap();
        let (sorted, _) = runtime_data_binding(r#"{"a":"test","b":1,"c":{"d":"e"}}"#).unwrap();
        let expected = hex::decode(
            "e71ce8e70d814ba6639c3612ebee0ff1f76f650f8dbb5e47157e0f3f525cd22c4597480a186427c813ca941da78870c3",
        )
        .unwrap();
        assert_eq!(reordered, sorted);
        assert_eq!(reordered, expected);
    }

    #[rstest]
    #[case(&[("nonce", "!!!")], "base64")]
    #[case(&[("nonce", "Y2g=")], "base64")]
    #[case(&[("foo", "bar")], "foo")]
    #[case(&[("nonce", "Y2hhbGxlbmdl"), ("foo", "bar")], "foo")]
    #[case(&[("nonce", "Y2hhbGxlbmdl"), ("runtime_data", "{}")], "only one")]
    #[case(&[("runtime_data", "not-json")], "JSON")]
    #[case(&[("runtime_data", "{")], "JSON")]
    #[tokio::test]
    async fn get_token(#[case] entries: &[(&str, &str)], #[case] message: &str) {
        let getter = CoCoASTokenGetter {
            as_uri: "http://127.0.0.1:9".into(),
        };
        let err = getter
            .get_token(&params(entries))
            .await
            .expect_err("get_token");
        assert!(err.to_string().contains(message), "{err:#}");
    }
}
