// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::config::coco_as::CoCoASConfig;

use anyhow::*;
use attester::{detect_tee_type, BoxedAttester};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

#[derive(Default)]
pub struct CoCoASTokenGetter {
    as_uri: String,
}

impl CoCoASTokenGetter {
    pub async fn get_token(&self) -> Result<Vec<u8>> {
        let primary_tee = detect_tee_type();
        let attester = BoxedAttester::try_from(primary_tee)?;
        let evidence = attester.get_evidence(vec![]).await?;

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
