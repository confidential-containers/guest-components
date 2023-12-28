// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Credentials to access aliyun KMS

use anyhow::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use serde_json::Value;
use url::form_urlencoded::byte_serialize;

#[derive(Clone, Debug)]
pub(crate) struct CredentialEcsRamRole {
    ecs_ram_role_name: String,
}

// implement CredentialEcsRamRole related function
impl CredentialEcsRamRole {
    pub(crate) fn new(ecs_ram_role_name: &str) -> Self {
        Self {
            ecs_ram_role_name: ecs_ram_role_name.to_string(),
        }
    }

    pub(crate) async fn get_session_credential(&self) -> Result<(String, String, String)> {
        let request_url = format!(
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/{}",
            self.ecs_ram_role_name
        );

        let response = reqwest::get(&request_url).await?;
        let body = if response.status().is_success() {
            response.text().await?
        } else {
            bail!(
                "Request session_credential failed with status: {}",
                response.status(),
            );
        };
        let body_json: Value = serde_json::from_str(&body)?;

        let session_ak = body_json
            .get("AccessKeyId")
            .ok_or(anyhow::anyhow!("get AccessKeyId fail"))?
            .as_str()
            .ok_or(anyhow::anyhow!("get AccessKeyId str fail"))?
            .to_string();
        let session_sk = body_json
            .get("AccessKeySecret")
            .ok_or(anyhow::anyhow!("get AccessKeySecret fail"))?
            .as_str()
            .ok_or(anyhow::anyhow!("get AccessKeySecret str fail"))?
            .to_string();
        let token = body_json
            .get("SecurityToken")
            .ok_or(anyhow::anyhow!("get SecurityToken fail"))?
            .as_str()
            .ok_or(anyhow::anyhow!("get SecurityToken str fail"))?
            .to_string();

        Ok((session_ak, session_sk, token))
    }

    pub(crate) fn sign(&self, str_to_sign: &str, secret: &str) -> Result<String> {
        let pkey = PKey::hmac(secret.as_bytes())?;
        let mut signer = Signer::new(MessageDigest::sha1(), &pkey)?;
        signer.update(str_to_sign.as_bytes())?;
        let signature = signer.sign_to_vec()?;
        Ok(STANDARD.encode(signature))
    }

    pub(crate) fn urlencode_openapi(&self, s: &str) -> String {
        let s: String = byte_serialize(s.as_bytes()).collect();
        s.replace('+', "%20")
            .replace('*', "%2A")
            .replace("%7E", "~")
    }
}
