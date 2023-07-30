// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use async_trait::async_trait;
use attester::{detect_tee_type, BoxedAttester};
use kbs_types::Tee;

use super::EvidenceProvider;

pub struct NativeEvidenceProvider(BoxedAttester);

impl NativeEvidenceProvider {
    pub fn new() -> Result<Self> {
        let tee = detect_tee_type()?;
        Ok(Self(tee.try_into()?))
    }
}

#[async_trait]
impl EvidenceProvider for NativeEvidenceProvider {
    async fn get_evidence(&self, runtime_data: Vec<u8>) -> Result<String> {
        self.0.get_evidence(runtime_data).await
    }

    async fn get_tee_type(&self) -> Result<Tee> {
        detect_tee_type()
    }
}
