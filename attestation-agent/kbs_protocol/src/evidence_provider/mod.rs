// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod native;
pub use native::*;

pub mod mock;
pub use mock::*;

use crate::Result;
use async_trait::async_trait;
use kbs_types::Tee;

#[async_trait]
pub trait EvidenceProvider: Send + Sync {
    /// Get evidence with nonce and TEE held data included
    async fn get_evidence(&self, nonce: String, tee_data: String) -> Result<String>;

    /// Get the underlying Tee type
    async fn get_tee_type(&self) -> Result<Tee>;
}
