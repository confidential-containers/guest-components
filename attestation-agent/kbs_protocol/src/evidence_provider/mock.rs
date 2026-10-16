// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
use attester::TeeEvidence;
use kbs_types::Tee;

use super::{EvidenceProvider, TeeInfo, TotalTeeInfo};

use crate::Result;

#[derive(Default)]
pub struct MockedEvidenceProvider {}

#[async_trait]
impl EvidenceProvider for MockedEvidenceProvider {
    async fn primary_evidence(&self, _runtime_data: Vec<u8>) -> Result<TeeEvidence> {
        Ok("test evidence".into())
    }

    async fn get_additional_evidence(&self, _runtime_data: Vec<u8>) -> Result<String> {
        Ok("".into())
    }

    async fn get_tee_type(&self) -> Result<Tee> {
        Ok(Tee::Sample)
    }

    async fn get_tee_metadata(&self) -> Result<TotalTeeInfo> {
        Ok(TotalTeeInfo {
            primary_tee: TeeInfo {
                tee: Tee::Sample,
                metadata: None,
            },
            additional_tees: vec![],
        })
    }
}
