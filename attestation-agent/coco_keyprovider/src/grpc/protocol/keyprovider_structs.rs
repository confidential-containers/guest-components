// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyProviderInput {
    // Operation is either "keywrap" or "keyunwrap"
    // attestation-agent can only handle the case of "keyunwrap"
    op: String,
    // For attestation-agent, keywrapparams should be empty.
    pub keywrapparams: KeyWrapParams,
    pub keyunwrapparams: KeyUnwrapParams,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyWrapParams {
    // For attestation-agent, ec is null
    pub ec: Option<Ec>,
    // For attestation-agent, optsdata is null
    pub optsdata: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ec {
    #[serde(rename = "Parameters")]
    pub parameters: HashMap<String, Vec<String>>,
    #[serde(rename = "DecryptConfig")]
    pub decrypt_config: Dc,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyUnwrapParams {
    pub dc: Option<Dc>,
    pub annotation: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Dc {
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
