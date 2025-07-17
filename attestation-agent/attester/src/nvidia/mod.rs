// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, TeeEvidence};
use anyhow::{bail, Context, Result};
use base64::Engine;
use log::warn;
use nvml_wrapper::{enums::device::DeviceArchitecture, Nvml};
use serde::Serialize;

pub fn detect_platform() -> bool {
    // Return true iff one GPU is found and it has CC mode set.
    match Nvml::init() {
        Ok(nvml) => {
            nvml.device_count().is_ok_and(|count| count == 1)
                && nvml
                    .device_by_index(0)
                    .is_ok_and(|device| device.is_cc_enabled().unwrap_or_default())
        }
        Err(_) => false,
    }
}

/// NRAS knows about "switch" and "gpu" but the expected evidence
/// content is the same. nvidia-attester can compose a list of
/// all CC enabled nvml/nscq devices using this evidence struct.
#[derive(Serialize)]
struct NvDeviceReportAndCert {
    arch: DeviceArchitecture,
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
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<TeeEvidence> {
        let nvml = Nvml::init()?;
        let devices = nvml.device_count()?;

        let mut device_evidence_list = vec![];
        let b64_engine = base64::engine::general_purpose::STANDARD;

        if report_data.len() < 32 {
            warn!("NVIDIA Attester: Report data must be at least 32 bytes");
        }

        let nonce: [u8; 32] = report_data[0..32].try_into()?;

        for index in 0..devices {
            let device = nvml.device_by_index(index)?;

            let report = device
                .confidential_compute_gpu_attestation_report(nonce)
                .context("Failed to get attestation report for device {index}")?;

            let certificate = device
                .confidential_compute_gpu_certificate()
                .context("Failed to get certificate for device {index}")?;

            let dev_arch = device
                .architecture()
                .context("Failed to get architecture for device {index}")?;

            let dev_uuid = device
                .uuid()
                .context("Failed to get UUID for device {index}")?;

            device_evidence_list.push(NvDeviceReportAndCert {
                arch: dev_arch,
                uuid: dev_uuid,
                evidence: b64_engine.encode(hex::encode(report.attestation_report)),
                certificate: b64_engine.encode(certificate.attestation_cert_chain),
            });

            device
                .set_confidential_compute_state(true)
                .context("Failed to set device {index} to ready state")?;

            // Run final sanity check to ensure the device confidential computing mode is enabled,
            // it's in a production environment, and accepting client requests.
            if !device
                .check_confidential_compute_status()
                .is_ok_and(|status| status == true)
            {
                bail!("NVIDIA attester: device {index} CC status check failed")
            }
        }

        let full_evidence = NvDeviceEvidence {
            device_evidence_list,
        };

        serde_json::to_value(&full_evidence).context("Serialize NVIDIA evidence failed")
    }
}
