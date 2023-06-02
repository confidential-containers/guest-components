// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use crypto::{self, TeeKey, WrapType, AES_256_GCM_ALGORITHM, RSA_ALGORITHM};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

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

#[derive(Serialize, Deserialize)]
struct ProtectedHeader {
    // enryption algorithm for encrypted key
    alg: String,
    // encryption algorithm for payload
    enc: String,
}

pub fn decrypt_response(response: &Response, tee_key: TeeKey) -> Result<Vec<u8>> {
    // deserialize the jose header and check that the key type matches
    let protected: ProtectedHeader = serde_json::from_str(&response.protected)?;
    if protected.alg != RSA_ALGORITHM {
        return Err(anyhow!("Algorithm mismatch for wrapped key."));
    }

    // unwrap the wrapped key
    let wrapped_symkey: Vec<u8> =
        base64::decode_config(&response.encrypted_key, base64::URL_SAFE_NO_PAD)?;
    let symkey: Vec<u8> = tee_key.decrypt(wrapped_symkey)?;

    let iv = base64::decode_config(&response.iv, base64::URL_SAFE_NO_PAD)?;
    let ciphertext = base64::decode_config(&response.ciphertext, base64::URL_SAFE_NO_PAD)?;

    let plaintext = match protected.enc.as_str() {
        AES_256_GCM_ALGORITHM => crypto::decrypt(
            Zeroizing::new(symkey),
            ciphertext,
            iv,
            WrapType::Aes256Gcm.as_ref(),
        )?,
        _ => {
            bail!("Unsupported algorithm: {}", protected.enc.clone());
        }
    };

    Ok(plaintext)
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
