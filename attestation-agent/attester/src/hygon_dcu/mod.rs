// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, TeeEvidence};
use anyhow::{Context, Result};
use csv_rs::api::dcu::{AttestationReport, DcuDevice};
use kbs_types::Tee;
use serde::{Deserialize, Serialize};
use std::{cmp::min, fs, path::Path};
use tracing::warn;

const DCU_NODES_DIR: &str = "/sys/devices/virtual/kfd/kfd/topology/nodes";

#[derive(Serialize, Deserialize)]
struct DcuEvidence {
    attestation_reports: Vec<AttestationReport>,
}

#[derive(Debug, Default)]
pub struct DcuAttester {}

impl std::fmt::Display for DcuAttester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("hygon-dcu-attester")
    }
}

#[async_trait::async_trait]
impl Attester for DcuAttester {
    fn detect_tee(&self) -> Option<Tee> {
        if !Path::new("/dev/mkfd").exists() {
            return None;
        }

        let std::result::Result::Ok(entries) = fs::read_dir(DCU_NODES_DIR) else {
            warn!("Cannot read DCU nodes directory: {DCU_NODES_DIR}");
            return None;
        };

        for entry in entries {
            let std::result::Result::Ok(entry) = entry else {
                warn!("Cannot read DCU node entry");
                continue;
            };

            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            if file_name_str != "." && file_name_str != ".." {
                return Some(Tee::HygonDcu);
            }
        }

        None
    }

    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<TeeEvidence> {
        let mut mnonce = [0u8; 64];
        if report_data.len() > 64 {
            warn!("DCU Attester: maximum report data size is 64 bytes, truncating input");
        }
        report_data.resize(64, 0);
        mnonce.copy_from_slice(&report_data[0..min(64, report_data.len())]);

        let mut dcu_device = DcuDevice::new()?;
        let attestation_reports = dcu_device.get_report(mnonce)?;
        let evidence = DcuEvidence {
            attestation_reports,
        };

        serde_json::to_value(&evidence).context("Serialize Hygon DCU evidence failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_csv_get_evidence() {
        let attester = DcuAttester::default();
        let report_data: Vec<u8> = vec![0; 16];

        let evidence = attester.get_evidence(report_data).await;
        assert!(evidence.is_ok());
    }
}
