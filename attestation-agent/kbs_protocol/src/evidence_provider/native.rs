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
        let tee = detect_tee_type().try_into().map_err(|e| {
            Error::NativeEvidenceProvider(format!("failed to initialize tee driver: {e:?}"))
        })?;
        Ok(Self(tee))
    }
}

#[async_trait]
impl EvidenceProvider for NativeEvidenceProvider {
    async fn get_evidence(&self, runtime_data: Vec<u8>) -> Result<String> {
        self.0
            .get_evidence(runtime_data)
            .await
            .map_err(|e| Error::GetEvidence(e.to_string()))
    }

    async fn get_tee_type(&self) -> Result<Tee> {
        Ok(detect_tee_type())
    }

    async fn get_derived_key(&self, root_key_hint: &[u8], context: Vec<u8>) -> Result<Vec<u8>> {
        self.0
            .get_derived_key(root_key_hint, context)
            .await
            .map_err(|e| Error::GetDerivedKey(e.to_string()))
    }
}
