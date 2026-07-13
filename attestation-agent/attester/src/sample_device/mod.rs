// Copyright (c) 2025 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, TeeEvidence};
use anyhow::*;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::env;

// The sample device attester can be enabled
// vi an environment variable.
pub fn detect_platform() -> bool {
    env::var("ENABLE_SAMPLE_DEVICE").is_ok()
}

#[derive(Serialize, Deserialize, Debug)]
struct SampleDeviceEvidence {
    svn: String,
    report_data: String,
}

#[derive(Debug, Default)]
pub struct SampleDeviceAttester {}

#[async_trait::async_trait]
impl Attester for SampleDeviceAttester {
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<TeeEvidence> {
        let evidence = SampleDeviceEvidence {
            svn: "2".to_string(),
            report_data: base64::engine::general_purpose::STANDARD.encode(report_data),
        };

        serde_json::to_value(&evidence).context("Failed to serialize sample evidence.")
    }
}
