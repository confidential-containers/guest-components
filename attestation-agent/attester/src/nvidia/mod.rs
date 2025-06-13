// Copyright (c) 2025 Confidential Containers
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, TeeEvidence};
use anyhow::{Context, Result};
use base64::Engine;
use nvml_wrapper::{enums::device::DeviceArchitecture, Nvml};
use serde::Serialize;

pub fn detect_platform() -> bool {
    // TODO: loop all devices here to check their CC status?
    match Nvml::init() {
        Ok(nvml) => nvml
            .device_count()
            .map_or_else(|_| false, |count| count > 0),
        Err(_) => false,
    }
}

/// NRAS knows about "switch" and "gpu" but the expected evidence
/// content is the same. nvidia-attester can compose a list of
/// all CC enabled nvml devices using this evidence struct.
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

        for index in 0..devices {
            let device = nvml.device_by_index(index)?;

            // Take the first half of the reportdata hash as the nonce (the hash includes the KBS protocol nonce)
            let nonce: [u8; 32] = report_data[0..32].try_into()?;

            // TODO: refactor once NMVL knows about other CC device types
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
                evidence: b64_engine.encode(report.attestation_report),
                certificate: b64_engine.encode(certificate.attestation_cert_chain),
            });
        }

        let full_evidence = NvDeviceEvidence {
            device_evidence_list,
        };

        serde_json::to_value(&full_evidence).context("Serialize NVIDIA evidence failed")
    }
}
