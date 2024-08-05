// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::config::coco_as::CoCoASConfig;

use super::GetToken;
use anyhow::*;
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

#[derive(Default)]
pub struct CoCoASTokenGetter {
    as_uri: String,
}

#[async_trait]
impl GetToken for CoCoASTokenGetter {
    async fn get_token(&self) -> Result<Vec<u8>> {
        let tee_type = attester::detect_tee_type();
        let attester = attester::BoxedAttester::try_from(tee_type)?;
        let evidence = attester.get_evidence(vec![]).await?;

        let request_body = serde_json::json!({
            "tee": serde_json::to_string(&tee_type)?,
            "evidence": URL_SAFE_NO_PAD.encode(evidence.as_bytes()),
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
