// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, TeeEvidence};
use anyhow::{anyhow, Context, Result};
use nv_attestation_sdk::{GpuEvidenceSource, Nonce, NvatSdk, SdkOptions, SwitchEvidenceSource};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use strum::{Display, EnumString};
use tracing::warn;

static INIT: OnceLock<Result<()>> = OnceLock::new();

const NVIDIA_NONCE_SIZE: usize = 32;

/// The NVAT SDK should be initialized exactly once.
/// The SDK object should not be dropped until all calls
/// to the SDK are finished.
/// Since we have no way of knowing when there will be no
/// more calls to the SDK, keep the SDK object indefinitely.
/// This shouldn't cause any problems in the CoCo use case.
fn ensure_sdk_init() -> Result<()> {
    INIT.get_or_init(|| -> Result<()> {
        let opts = SdkOptions::new()?;
        let sdk = NvatSdk::init(opts)?;
        std::mem::forget(sdk);
        Ok(())
    })
    .as_ref()
    .map_err(|e| anyhow!("Failed to initialize SDK: {e}"))?;

    Ok(())
}

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
    if ensure_sdk_init().is_err() {
        warn!("NVIDIA Attestation SDK could not be initialized.");
        return false;
    };

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
    #[serde(default = "default_uuid")]
    uuid: String,
    evidence: String,
    certificate: String,
}

/// UUID isn't used for attestation and isn't reported by the NVAT
/// bindings. To maintain backwards comptability, keep UUID in the
/// struct, but don't require it.
fn default_uuid() -> String {
    "unknown".to_string()
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
    ensure_sdk_init()?;

    let nonce = match report_data {
        Some(data_vec) => Nonce::from_hex(&hex::encode(data_vec))?,
        None => Nonce::generate(32)?,
    };

    let mut evidence = vec![];

    match GpuEvidenceSource::from_nvml() {
        Ok(gpu_source) => match gpu_source.collect(&nonce) {
            Ok(gpu_evidence) => {
                if !gpu_evidence.is_empty() {
                    let gpu_evidence: Vec<NvDeviceReportAndCert> =
                        serde_json::from_str(&gpu_evidence.to_json()?)?;
                    evidence.extend(gpu_evidence);
                }
            }
            Err(e) => warn!("Failed to get gpu evidence: {}", e),
        },
        Err(e) => warn!("Failed to initialize gpu evidence source: {}", e),
    }

    match SwitchEvidenceSource::from_nscq() {
        Ok(switch_source) => match switch_source.collect(&nonce) {
            Ok(switch_evidence) => {
                if !switch_evidence.is_empty() {
                    let switch_evidence: Vec<NvDeviceReportAndCert> =
                        serde_json::from_str(&switch_evidence.to_json()?)?;
                    evidence.extend(switch_evidence);
                }
            }
            Err(e) => warn!("Failed to get switch evidence: {}", e),
        },
        Err(e) => warn!("Failed to initialize switch evidence source: {}", e),
    }

    Ok(evidence)
}
