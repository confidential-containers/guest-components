// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
use kbs_types::Tee;

use super::EvidenceProvider;

use crate::Result;

#[derive(Default)]
pub struct MockedEvidenceProvider {}

#[async_trait]
impl EvidenceProvider for MockedEvidenceProvider {
    async fn get_evidence(&self, _runtime_data: Vec<u8>) -> Result<String> {
        Ok("test evidence".into())
    }

    async fn get_tee_type(&self) -> Result<Tee> {
        Ok(Tee::Sample)
    }
}
