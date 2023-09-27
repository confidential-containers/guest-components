// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
use attester::{detect_tee_type, BoxedAttester};
use kbs_types::Tee;

use super::EvidenceProvider;

use crate::{Error, Result};

pub struct NativeEvidenceProvider(BoxedAttester);

impl NativeEvidenceProvider {
    pub fn new() -> Result<Self> {
        let tee = detect_tee_type()
            .ok_or_else(|| Error::GetTeeTypeFailed("no supported Tee type detected.".into()))?
            .try_into()
            .map_err(|e| {
                Error::NativeEvidenceProvider(format!("failed to initialize tee driver: {e}"))
            })?;
        Ok(Self(tee))
    }
}

#[async_trait]
impl EvidenceProvider for NativeEvidenceProvider {
    async fn get_evidence(&self, nonce: String, tee_data: String) -> Result<String> {
        self.0
            .get_evidence(nonce, tee_data)
            .await
            .map_err(|e| Error::GetEvidence(e.to_string()))
    }

    async fn get_tee_type(&self) -> Result<Tee> {
        detect_tee_type()
            .ok_or_else(|| Error::GetTeeTypeFailed("no supported Tee type detected.".into()))
    }
}
