// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::kbc_modules::cc_kbc::crypto::*;
use anyhow::*;
use serde::{Deserialize, Serialize};

pub const KBS_PROTOCOL_VERSION: &str = "0.1.0";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Request {
    version: String,
    tee: String,

    // Reserved field.
    #[serde(rename = "extra-params")]
    pub extra_params: String,
}

impl Request {
    pub fn new(tee: String) -> Request {
        Request {
            version: KBS_PROTOCOL_VERSION.to_string(),
            tee,
            extra_params: "".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Challenge {
    // Nonce from KBS to prevent replay attack.
    pub nonce: String,

    // Reserved field.
    #[serde(rename = "extra-params")]
    pub extra_params: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Attestation {
    // The public key of TEE.
    // Its hash is included in `tee-evidence`.
    #[serde(rename = "tee-pubkey")]
    pub tee_pubkey: String,

    // TEE quote, different TEE type has different format of the content.
    #[serde(rename = "tee-evidence")]
    pub tee_evidence: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Response {
    pub protected: String,
    pub encrypted_key: String,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

impl Response {
    // Use TEE's private key to decrypt output of Response.
    pub fn decrypt_output(&self, tee_key: TeeKey) -> Result<Vec<u8>> {
        decrypt_response(self, tee_key)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorDetails {
    pub info: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorResponse {
    pub error: ErrorDetails,
}

impl ErrorResponse {
    pub fn error_info(&self) -> String {
        self.error.info.clone()
    }
}
