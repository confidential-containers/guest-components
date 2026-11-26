// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, TeeEvidence};
use anyhow::*;
use base64::Engine;
use kbs_types::Tee;
use serde::{Deserialize, Serialize};

// A simple example of TEE evidence.
#[derive(Serialize, Deserialize, Debug)]
struct SampleQuote {
    svn: String,
    report_data: String,
}

#[derive(Debug, Default)]
pub struct SampleAttester {}

impl std::fmt::Display for SampleAttester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("sample-attester")
    }
}

#[async_trait::async_trait]
impl Attester for SampleAttester {
    fn detect_tee(&self) -> Option<Tee> {
        // Sample attester is always supported.
        Some(Tee::Sample)
    }

    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<TeeEvidence> {
        let evidence = SampleQuote {
            svn: "1".to_string(),
            report_data: base64::engine::general_purpose::STANDARD.encode(report_data),
        };

        serde_json::to_value(&evidence).context("Serialize sample evidence failed")
    }

    fn supports_runtime_measurement(&self) -> bool {
        false
    }
}
