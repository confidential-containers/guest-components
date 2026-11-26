// Copyright (c) 2025 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, TeeEvidence};
use anyhow::*;
use base64::Engine;
use kbs_types::Tee;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Serialize, Deserialize, Debug)]
struct SampleDeviceEvidence {
    svn: String,
    report_data: String,
}

#[derive(Debug, Default)]
pub struct SampleDeviceAttester {}

impl std::fmt::Display for SampleDeviceAttester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("sample-device-attester")
    }
}

#[async_trait::async_trait]
impl Attester for SampleDeviceAttester {
    fn detect_tee(&self) -> Option<Tee> {
        // The sample device attester can be enabled via an environment variable.
        env::var("ENABLE_SAMPLE_DEVICE")
            .is_ok()
            .then_some(Tee::SampleDevice)
    }

    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<TeeEvidence> {
        let evidence = SampleDeviceEvidence {
            svn: "2".to_string(),
            report_data: base64::engine::general_purpose::STANDARD.encode(report_data),
        };

        serde_json::to_value(&evidence).context("Failed to serialize sample evidence.")
    }
}
