// Copyright (c) 2026 NVIDIA Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{Attester, TeeEvidence};
use anyhow::{bail, Result};

pub fn detect_platform() -> bool {
    false
}

#[derive(Debug, Default)]
pub struct NvAttester {}

#[async_trait::async_trait]
impl Attester for NvAttester {
    async fn get_evidence(&self, _report_data: Vec<u8>) -> Result<TeeEvidence> {
        bail!("NVIDIA attestation is not supported on this platform")
    }
}
