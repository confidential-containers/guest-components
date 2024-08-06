// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str;
use std::vec::Vec;

#[macro_export]
macro_rules! format_error {
    ($err:expr) => {{
        let mut error_string = format!("{}", $err);
        let mut current_error = $err.source();
        while let Some(source) = current_error {
            error_string.push_str(&format!("\nCaused by: {}", source));
            current_error = source.source();
        }
        error_string
    }};
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct KeyProviderInput {
    // Operation is either "keywrap" or "keyunwrap"
    // attestation-agent can only handle the case of "keyunwrap"
    op: String,
    // For attestation-agent, keywrapparams should be empty.
    pub keywrapparams: KeyWrapParams,
    pub keyunwrapparams: KeyUnwrapParams,
}

impl KeyProviderInput {
    pub fn get_annotation(&self) -> Result<Vec<u8>> {
        let annotation_base64 = self
            .keyunwrapparams
            .annotation
            .as_ref()
            .ok_or_else(|| anyhow!("Illegal UnwrapKey request: no AnnotationPacket given."))?;

        let engine = base64::engine::general_purpose::STANDARD;
        let annotation = engine.decode(annotation_base64)?;
        Ok(annotation)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct KeyWrapParams {
    // For attestation-agent, ec is null
    pub ec: Option<Ec>,
    // For attestation-agent, optsdata is null
    pub optsdata: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct Ec {
    #[serde(rename = "Parameters")]
    pub parameters: HashMap<String, Vec<String>>,
    #[serde(rename = "DecryptConfig")]
    pub decrypt_config: Dc,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct KeyUnwrapParams {
    pub dc: Option<Dc>,
    pub annotation: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct Dc {
    // Name is expected to be "attestation-agent".
    // Values are expected to be base-64 encoded.
    #[serde(rename = "Parameters")]
    pub parameters: HashMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyWrapOutput {
    pub keywrapresults: KeyWrapResults,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyWrapResults {
    pub annotation: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyUnwrapOutput {
    pub keyunwrapresults: KeyUnwrapResults,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyUnwrapResults {
    pub optsdata: Vec<u8>,
}
