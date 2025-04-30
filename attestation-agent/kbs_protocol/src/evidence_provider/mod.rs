// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod native;
pub use native::*;

pub mod mock;
pub use mock::*;

#[cfg(feature = "aa_ttrpc")]
pub mod aa_ttrpc;
#[cfg(feature = "aa_ttrpc")]
pub use aa_ttrpc::*;

use crate::Result;
use async_trait::async_trait;
use crypto::HashAlgorithm;
use kbs_types::{Tee, TeePubKey};

#[async_trait]
pub trait EvidenceProvider: Send + Sync {
    /// Get evidence with as runtime data (report data, challege)
    async fn get_evidence(
        &self,
        tee_pubkey: TeePubKey,
        nonce: String,
        hash_algorithm: HashAlgorithm,
    ) -> Result<String>;

    /// Get the underlying Tee type
    async fn get_tee_type(&self) -> Result<Tee>;
}
