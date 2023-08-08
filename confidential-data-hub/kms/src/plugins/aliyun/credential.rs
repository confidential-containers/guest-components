// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Credentials to access aliyun KMS

use anyhow::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::{
    pkcs12::Pkcs12,
    pkey::{PKey, Private},
    sign::Signer,
};
use serde::Deserialize;

#[derive(Clone, Debug)]
pub(crate) struct Credential {
    pub(crate) client_key_id: String,
    private_key: PKey<Private>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ClientKey {
    key_id: String,
    private_key_data: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Password {
    client_key_password: String,
}

impl Credential {
    pub(crate) fn new(client_key: &str, pswd: &str) -> Result<Self> {
        let ck: ClientKey = serde_json::from_str(client_key)?;

        let password: Password = serde_json::from_str(pswd)?;

        let private_key_der = STANDARD.decode(ck.private_key_data.as_bytes())?;
        let pkcs12 = Pkcs12::from_der(&private_key_der)?;
        let parsed = pkcs12.parse2(&password.client_key_password)?;
        let private_key = parsed
            .pkey
            .ok_or_else(|| anyhow!("no private key included in pkcs12"))?;

        let credential = Credential {
            client_key_id: ck.key_id.clone(),
            private_key,
        };

        Ok(credential)
    }

    pub(crate) fn generate_bear_auth(&self, str_to_sign: &str) -> Result<String> {
        let mut signer = Signer::new(openssl::hash::MessageDigest::sha256(), &self.private_key)?;
        signer.update(str_to_sign.as_bytes())?;
        let signature = signer.sign_to_vec()?;

        Ok(format!("Bearer {}", STANDARD.encode(signature)))
    }
}
