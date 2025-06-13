// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
use crypto::HashAlgorithm;
use kbs_types::{Tee, TeePubKey};

use super::EvidenceProvider;

use crate::Result;

#[derive(Default)]
pub struct MockedEvidenceProvider {}

#[async_trait]
impl EvidenceProvider for MockedEvidenceProvider {
    async fn get_evidence(
        &self,
        _tee_pubkey: TeePubKey,
        _nonce: String,
        _hash_algorithm: HashAlgorithm,
    ) -> Result<String> {
        Ok("test evidence".into())
    }

    async fn get_tee_type(&self) -> Result<Tee> {
        Ok(Tee::Sample)
    }
}
