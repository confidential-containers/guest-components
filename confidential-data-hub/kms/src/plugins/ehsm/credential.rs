// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Credentials to access eHSM-KMS

// use anyhow::*;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Credential {
    pub _app_id: String,
    pub api_key: String,
}
