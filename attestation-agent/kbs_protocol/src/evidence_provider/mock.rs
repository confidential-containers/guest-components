// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
use attester::TeeEvidence;
use base64::Engine;
use kbs_types::Tee;
use serde::{Deserialize, Serialize};

use super::EvidenceProvider;

use crate::Result;

#[derive(Serialize, Deserialize, Debug)]
struct SampleQuote {
    svn: String,
    report_data: String,
}

#[derive(Default)]
pub struct MockedEvidenceProvider {}

#[async_trait]
impl EvidenceProvider for MockedEvidenceProvider {
    async fn primary_evidence(&self, runtime_data: Vec<u8>) -> Result<TeeEvidence> {
        let evidence = SampleQuote {
            svn: "1".to_string(),
            report_data: base64::engine::general_purpose::STANDARD.encode(runtime_data),
        };

        serde_json::to_value(&evidence)
            .map_err(|e| crate::Error::GetEvidence(format!("Serialize sample evidence failed: {e}")))
    }

    async fn get_additional_evidence(&self, _runtime_data: Vec<u8>) -> Result<String> {
        Ok("".into())
    }

    async fn get_tee_type(&self) -> Result<Tee> {
        Ok(Tee::Sample)
    }
}
