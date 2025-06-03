// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, TeeEvidence};
use anyhow::*;
use base64::Engine;
use log::warn;
use serde::{Deserialize, Serialize};

// Sample attester is always supported
pub fn detect_platform() -> bool {
    true
}

// A simple example of TEE evidence.
#[derive(Serialize, Deserialize, Debug)]
struct SampleQuote {
    svn: String,
    report_data: String,
}

#[derive(Debug, Default)]
pub struct SampleAttester {}

#[async_trait::async_trait]
impl Attester for SampleAttester {
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<TeeEvidence> {
        let evidence = SampleQuote {
            svn: "1".to_string(),
            report_data: base64::engine::general_purpose::STANDARD.encode(report_data),
        };

        serde_json::to_value(&evidence).context("Serialize sample evidence failed")
    }

    async fn extend_runtime_measurement(
        &self,
        _event_digest: Vec<u8>,
        _register_index: u64,
    ) -> Result<()> {
        warn!("The Sample Attester does not extend any runtime measurement.");
        Ok(())
    }

    async fn get_runtime_measurement(&self, _pcr_index: u64) -> Result<Vec<u8>> {
        Ok(vec![])
    }
}
