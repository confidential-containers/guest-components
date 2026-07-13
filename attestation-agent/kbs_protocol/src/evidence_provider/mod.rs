// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod native;

use attester::TeeEvidence;
pub use native::*;

pub mod mock;
pub use mock::*;

#[cfg(feature = "aa_ttrpc")]
pub mod aa_ttrpc;
#[cfg(feature = "aa_ttrpc")]
pub use aa_ttrpc::*;

use crate::Result;
use async_trait::async_trait;
use kbs_types::Tee;

#[async_trait]
pub trait EvidenceProvider: Send + Sync {
    /// Get evidence with as runtime data
    async fn primary_evidence(&self, runtime_data: Vec<u8>) -> Result<TeeEvidence>;

    /// Get evidences of devices
    async fn get_additional_evidence(&self, runtime_data: Vec<u8>) -> Result<String>;

    /// Get the underlying Tee type
    async fn get_tee_type(&self) -> Result<Tee>;
}
