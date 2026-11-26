// Copyright (c) 2026 NVIDIA Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{Attester, TeeEvidence};
use anyhow::{Result, bail};
use kbs_types::Tee;

#[derive(Debug, Default)]
pub struct NvAttester {}

impl std::fmt::Display for NvAttester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("nvidia-attester")
    }
}

#[async_trait::async_trait]
impl Attester for NvAttester {
    fn detect_tee(&self) -> Option<Tee> {
        None
    }

    async fn get_evidence(&self, _report_data: Vec<u8>) -> Result<TeeEvidence> {
        bail!("NVIDIA attestation is not supported on this platform")
    }
}
