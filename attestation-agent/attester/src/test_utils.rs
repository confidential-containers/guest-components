// Copyright (c) 2026 Confidential Containers Authors
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::*;
use kbs_types::HashAlgorithm;

use crate::{Attester, TeeEvidence};

/// A TDX-like attester with per-register software RTMRs. `crash_after_extend` fails the
/// call after the extend lands, as a crash right after extending would.
#[derive(Default)]
pub struct FakeTdx {
    pub registers: Arc<Mutex<HashMap<u64, Vec<u8>>>>,
    pub crash_after_extend: bool,
}

impl FakeTdx {
    fn initial_value() -> Vec<u8> {
        vec![0; HashAlgorithm::Sha384.digest_len()]
    }
}

#[async_trait::async_trait]
impl Attester for FakeTdx {
    async fn get_evidence(&self, _: Vec<u8>) -> Result<TeeEvidence> {
        Ok(TeeEvidence::Null)
    }

    fn supports_runtime_measurement(&self) -> bool {
        true
    }

    async fn extend_runtime_measurement(&self, digest: Vec<u8>, pcr: u64) -> Result<()> {
        let mut registers = self.registers.lock().unwrap();
        let value = registers.entry(pcr).or_insert_with(Self::initial_value);
        let mut buf = value.clone();
        buf.extend_from_slice(&digest);
        *value = HashAlgorithm::Sha384.digest(&buf);
        if self.crash_after_extend {
            bail!("crash after extend");
        }
        Ok(())
    }

    async fn get_runtime_measurement(&self, pcr: u64) -> Result<Vec<u8>> {
        let registers = self.registers.lock().unwrap();
        Ok(registers
            .get(&pcr)
            .cloned()
            .unwrap_or_else(Self::initial_value))
    }

    fn pcr_to_ccmr(&self, pcr: u64) -> u64 {
        // Same mapping as the TDX attester.
        match pcr {
            1 | 7 => 1,
            2..=6 => 2,
            8..=15 => 3,
            _ => 4,
        }
    }

    fn ccel_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha384
    }
}
