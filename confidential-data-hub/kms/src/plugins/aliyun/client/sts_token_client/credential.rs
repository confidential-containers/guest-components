// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Credentials to access aliyun KMS

use anyhow::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::hmac::{self, Key, HMAC_SHA1_FOR_LEGACY_USE_ONLY};
use serde::Deserialize;
use url::form_urlencoded::byte_serialize;

#[derive(Deserialize)]
pub struct StsCredential {
    #[serde(rename = "AccessKeyId")]
    pub ak: String,

    #[serde(rename = "AccessKeySecret")]
    pub sk: String,

    #[serde(rename = "SecurityToken")]
    pub sts: String,
}

pub(crate) fn sign(str_to_sign: &str, secret: &str) -> Result<String> {
    let pkey = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret.as_bytes());
    let signature = hmac::sign(&pkey, str_to_sign.as_bytes());
    Ok(STANDARD.encode(signature))
}

pub(crate) fn urlencode_openapi(s: &str) -> String {
    let s: String = byte_serialize(s.as_bytes()).collect();
    s.replace('+', "%20")
        .replace('*', "%2A")
        .replace("%7E", "~")
}
