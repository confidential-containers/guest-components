// Copyright (c) 2023-2024 Arm Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::tsm_report::*;
use super::{Attester, TeeEvidence};
use anyhow::*;
use serde::{Deserialize, Serialize};

const CCA_CHALLENGE_SIZE: usize = 64;

pub fn detect_platform() -> bool {
    #[cfg(target_arch = "aarch64")]
    return TsmReportPath::new(TsmReportProvider::Cca).is_ok();
    #[cfg(not(target_arch = "aarch64"))]
    return false;
}

#[derive(Debug, Default)]
pub struct CcaAttester {}

#[derive(Serialize, Deserialize)]
struct CcaEvidence {
    /// CCA token
    token: Vec<u8>,
}

#[async_trait::async_trait]
impl Attester for CcaAttester {
    async fn get_evidence(&self, mut challenge: Vec<u8>) -> Result<TeeEvidence> {
        if challenge.len() > CCA_CHALLENGE_SIZE {
            bail!("CCA Attester: Challenge size must be {CCA_CHALLENGE_SIZE} bytes or less.");
        }

        challenge.resize(CCA_CHALLENGE_SIZE, 0);
        let tsm = TsmReportPath::new(TsmReportProvider::Cca)?;
        let token = tsm.attestation_report(TsmReportData::Cca(challenge))?;
        let evidence = CcaEvidence { token };
        let ev = serde_json::to_value(&evidence).context("Serialization of CCA evidence failed")?;
        Ok(ev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_cca_get_evidence() {
        let attester = CcaAttester::default();
        let report_data: Vec<u8> = vec![0; 48];
        let evidence = attester.get_evidence(report_data).await;
        assert!(evidence.is_ok());
    }
}
