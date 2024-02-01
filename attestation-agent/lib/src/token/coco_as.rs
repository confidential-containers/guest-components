// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::GetToken;
use anyhow::*;
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha384};

#[derive(Default)]
pub struct CoCoASTokenGetter {}

#[async_trait]
impl GetToken for CoCoASTokenGetter {
    async fn get_token(&self, as_uri: String, structured_runtime_data: &str) -> Result<Vec<u8>> {
        let structured_value: serde_json::Value = serde_json::from_str(structured_runtime_data)
            .context("Get Token Failed: Structured Runtime Data must be a JSON Map")?;

        // TODO: Request AS to get Nonce and insert the Nonce into structured runtime data JSON Map.

        let hash_materials =
            serde_json::to_vec(&structured_value).context("parse JSON structured data")?;
        let mut hasher = Sha384::new();
        hasher.update(hash_materials);
        let structured_data_digest = hasher.finalize().to_vec();

        let tee_type = attester::detect_tee_type();
        let attester = attester::BoxedAttester::try_from(tee_type)?;
        let evidence = attester.get_evidence(structured_data_digest).await?;

        let request_body = serde_json::json!({
            "tee": serde_json::to_string(&tee_type)?,
            "runtime_data": {
                "structured": structured_value
            },
            "runtime_data_hash_algorithm": "sha384",
            "evidence": URL_SAFE_NO_PAD.encode(evidence.as_bytes()),
        });

        let client = reqwest::Client::new();
        let res = client
            .post(as_uri)
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
