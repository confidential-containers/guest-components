// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
use attester::CompositeAttester;
use crypto::HashAlgorithm;
use kbs_types::{Tee, TeePubKey};

use super::EvidenceProvider;

use crate::{Error, Result};

pub struct NativeEvidenceProvider(CompositeAttester);

impl NativeEvidenceProvider {
    pub fn new() -> Result<Self> {
        Ok(Self(
            CompositeAttester::new().map_err(|e| Error::GetEvidence(e.to_string()))?,
        ))
    }
}

#[async_trait]
impl EvidenceProvider for NativeEvidenceProvider {
    async fn get_evidence(
        &self,
        tee_pubkey: TeePubKey,
        nonce: String,
        hash_algorithm: HashAlgorithm,
    ) -> Result<String> {
        self.0
            .composite_evidence(tee_pubkey, nonce, hash_algorithm)
            .await
            .map_err(|e| Error::GetEvidence(e.to_string()))
    }

    async fn get_tee_type(&self) -> Result<Tee> {
        Ok(self.0.tee_type())
    }
}
