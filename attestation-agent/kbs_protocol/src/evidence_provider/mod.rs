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
use kbs_types::Tee;

/// The EvidenceProvider is an interface between the kbs_protocol RCAR client
/// and the TEE attesters.
///
/// The native provider runs the attesters directly, while the
/// aa_ttrpc provider will connect to an attestation agent remotely
/// to get the evidence. The mock provider returns fake evidence.
#[async_trait]
pub trait EvidenceProvider: Send + Sync {
    /// Get evidence with as runtime data (report data, challenge)
    async fn get_evidence(&self, runtime_data: Vec<u8>) -> Result<String>;

    /// Get the underlying Tee type
    async fn get_tee_types(&self) -> Result<Vec<Tee>>;
}
