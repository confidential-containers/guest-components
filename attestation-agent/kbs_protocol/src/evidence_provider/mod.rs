// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod native;

use attester::TeeEvidence;
use kbs_types::Tee;
pub use native::*;

pub mod mock;
pub use mock::*;

#[cfg(feature = "aa_ttrpc")]
pub mod aa_ttrpc;
#[cfg(feature = "aa_ttrpc")]
pub use aa_ttrpc::*;
use serde::Serialize;
use serde_json::Value;

use crate::Result;
use async_trait::async_trait;

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct TotalTeeInfo {
    pub primary_tee: TeeInfo,
    pub additional_tees: Vec<TeeInfo>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct TeeInfo {
    pub tee: Tee,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[async_trait]
pub trait EvidenceProvider: Send + Sync {
    /// Get evidence with as runtime data
    async fn primary_evidence(&self, runtime_data: Vec<u8>) -> Result<TeeEvidence>;

    /// Get evidences of devices
    async fn get_additional_evidence(&self, runtime_data: Vec<u8>) -> Result<String>;

    /// Get the underlying primary Tee type
    async fn get_tee_type(&self) -> Result<Tee>;

    /// Get primary/additional TEE types together with optional metadata.
    async fn get_tee_metadata(&self) -> Result<TotalTeeInfo>;
}
