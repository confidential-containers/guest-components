// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, TeeEvidence};
use anyhow::{Context, Result};
use nv_attestation_sdk::{GpuEvidenceSource, Nonce, NvatSdk, SdkOptions, SwitchEvidenceSource};
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};
use tracing::{info, warn};

const NVIDIA_NONCE_SIZE: usize = 32;

#[derive(Debug, Deserialize, Display, EnumString, PartialEq, Serialize)]
#[strum(ascii_case_insensitive)]
enum Architecture {
    #[serde(alias = "BLACKWELL")]
    Blackwell,
    #[serde(alias = "HOPPER")]
    Hopper,
    LS10,
}

pub fn detect_platform() -> bool {
    match get_device_evidence(None) {
        Ok(ev) => !ev.is_empty(),
        Err(e) => {
            warn!("NVIDIA device detection failed due to: {}", e.to_string());
            false
        }
    }
}

/// NRAS knows about "switch" and "gpu" but the expected evidence
/// content is the same. nvidia-attester can compose a list of
/// all CC enabled nvml/nscq devices using this evidence struct.
#[derive(Deserialize, Serialize)]
struct NvDeviceReportAndCert {
    arch: Architecture,
    uuid: String,
    evidence: String,
    certificate: String,
}

#[derive(Serialize)]
struct NvDeviceEvidence {
    device_evidence_list: Vec<NvDeviceReportAndCert>,
}

#[derive(Debug, Default)]
pub struct NvAttester {}

#[async_trait::async_trait]
impl Attester for NvAttester {
    /// Generate evidence for the NVIDIA devices. A 32 byte nonce is taken from the first 32
    /// report_data bytes. report_data shorter than 32 bytes is zero padded.
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<TeeEvidence> {
        if report_data.len() < NVIDIA_NONCE_SIZE {
            report_data.resize(NVIDIA_NONCE_SIZE, 0);
        }

        let nonce: [u8; NVIDIA_NONCE_SIZE] = report_data[0..NVIDIA_NONCE_SIZE].try_into()?;

        let device_evidence_list = get_device_evidence(Some(nonce))?;

        let full_evidence = NvDeviceEvidence {
            device_evidence_list,
        };

        serde_json::to_value(&full_evidence).context("Serialize NVIDIA evidence failed")
    }
}

/// Internal helper for getting evidence from NVIDIA devices.
fn get_device_evidence(report_data: Option<[u8; 32]>) -> Result<Vec<NvDeviceReportAndCert>> {
    let opts = SdkOptions::new()?;
    let _sdk = NvatSdk::init(opts)?;

    let nonce = match report_data {
        Some(data_vec) => Nonce::from_hex(&hex::encode(data_vec))?,
        None => Nonce::generate(32)?,
    };

    let gpu_source = GpuEvidenceSource::from_nvml()?;
    let gpu_evidence = gpu_source.collect(&nonce)?;

    let switch_source = SwitchEvidenceSource::from_nscq()?;
    let switch_evidence = switch_source.collect(&nonce)?;

    if gpu_evidence.is_empty() && switch_evidence.is_empty() {
        info!("No NVIDIA GPUs or NVSwitches found.");
        return Ok(vec![]);
    }

    let mut gpu_evidence: Vec<NvDeviceReportAndCert> =
        serde_json::from_str(&gpu_evidence.to_json()?)?;
    let switch_evidence: Vec<NvDeviceReportAndCert> =
        serde_json::from_str(&switch_evidence.to_json()?)?;

    gpu_evidence.extend(switch_evidence);

    Ok(gpu_evidence)
}
