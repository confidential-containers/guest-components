// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! NVIDIA DPU (Data Processing Unit) Attester
//!
//! Collects attestation evidence from NVIDIA DPU devices (e.g., BlueField-3)
//! using the DICE (Device Identifier Composition Engine) certificate chain.
//!
//! The NVIDIA DPU attester reads hardware-rooted attestation evidence including:
//! - Alias certificate (leaf) containing device measurements
//! - DeviceID certificate signed by manufacturer root
//! - Firmware measurements from DICE layers
//!
//! Platform detection uses PCI device ID scanning to identify BlueField-3
//! hardware (vendor `15b3`, device `a2dc` for BF3 NIC or `a2da` for SoC bridge).

use super::{Attester, TeeEvidence};
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use p384::ecdsa::signature::Signer;
use p384::ecdsa::{Signature, SigningKey};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, base64::Base64};

/// PCI vendor ID for Mellanox/NVIDIA networking devices.
const NVIDIA_MLX_VENDOR_ID: &str = "15b3";
/// PCI device IDs that identify BlueField-3 (as opposed to ConnectX-7 or other NICs).
/// - a2dc: BF3 integrated NIC function
/// - a2da: BF3 SoC PCI bridge
const BF3_DEVICE_IDS: &[&str] = &["a2dc", "a2da"];

const PCI_DEVICES_PATH: &str = "/sys/bus/pci/devices";
const NVIDIA_DPU_NONCE_SIZE: usize = 64;

/// DICE alias private key path exposed by NVIDIA DOCA attestation service via sysfs.
/// Reference: NVIDIA DOCA DICE Programming Guide - "Key Exposure via sysfs"
const ALIAS_PRIVATE_KEY_PATH: &str = "/sys/kernel/security/tee/dice/alias_private_key";

/// Base path for DPU attestation attributes exposed via InfiniBand sysfs.
// TODO: dynamically discover InfiniBand device name instead of hardcoding mlx5_0.
// Multiple devices or different naming (mlx5_1, etc.) require enumeration.
const ATTESTATION_BASE_PATH: &str = "/sys/class/infiniband/mlx5_0/device/attestation";

/// Top-level NVIDIA DPU attestation evidence.
/// Versioned and supports multiple device entries for forward-compatibility.
#[derive(Debug, Serialize, Deserialize)]
pub struct NvidiaDpuEvidence {
    /// Evidence format version
    pub version: u32,
    /// Per-device attestation evidence entries
    pub devices: Vec<DpuDeviceEvidence>,
}

/// Evidence from a single DPU device.
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct DpuDeviceEvidence {
    /// Device architecture identifier (e.g. "bluefield3")
    pub architecture: String,
    /// DER-encoded DICE Alias certificate (leaf)
    #[serde_as(as = "Base64")]
    pub alias_cert: Vec<u8>,
    /// DER-encoded DICE DeviceID certificate
    #[serde_as(as = "Base64")]
    pub device_id_cert: Vec<u8>,
    /// Firmware measurements from DICE layers
    pub measurements: Vec<NvidiaDpuMeasurement>,
    /// Base64-encoded ECDSA P-384 signature of report_data using DICE alias private key
    pub report_data_signature: String,
}

/// A single DICE layer measurement
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct NvidiaDpuMeasurement {
    /// DICE layer index. Known values:
    /// - 0: ROM (immutable boot code)
    /// - 1: Firmware
    /// - 2: OS/Runtime
    /// Open to extension — future firmware versions may define additional layers.
    pub layer: u8,
    /// SHA-384 digest of the layer's code/config (fixed 48 bytes)
    #[serde_as(as = "Base64")]
    pub digest: [u8; 48],
}

/// Detect if NVIDIA BlueField-3 DPU hardware is available on the platform.
///
/// Scans PCI sysfs for devices matching the BF3 vendor:device IDs.
/// This distinguishes BlueField-3 from regular ConnectX NICs which have
/// different PCI device IDs.
pub fn detect_platform() -> bool {
    // Scan PCI devices for BF3-specific device IDs
    let Ok(entries) = std::fs::read_dir(PCI_DEVICES_PATH) else {
        return false;
    };
    for entry in entries.flatten() {
        let vendor_path = entry.path().join("vendor");
        let device_path = entry.path().join("device");

        let vendor = std::fs::read_to_string(&vendor_path)
            .unwrap_or_default()
            .trim()
            .trim_start_matches("0x")
            .to_lowercase();
        let device = std::fs::read_to_string(&device_path)
            .unwrap_or_default()
            .trim()
            .trim_start_matches("0x")
            .to_lowercase();

        if vendor == NVIDIA_MLX_VENDOR_ID
            && BF3_DEVICE_IDS.iter().any(|id| device == *id)
        {
            return true;
        }
    }

    false
}

/// Sign report_data with DICE alias private key for freshness binding.
/// Returns error if the key is unavailable (unsigned evidence is not acceptable).
fn sign_report_data(report_data: &[u8]) -> Result<String> {
    // DICE alias private key path from NVIDIA DOCA attestation service layout.
    // Reference: NVIDIA DOCA DICE Programming Guide, Section "Key Exposure via sysfs"
    let key_bytes = std::fs::read(ALIAS_PRIVATE_KEY_PATH)
        .context("DICE alias private key not available - cannot produce signed evidence")?;
    if key_bytes.len() != 48 {
        bail!("signing key must be exactly 48 bytes (P-384), got {}", key_bytes.len());
    }
    let signing_key = SigningKey::from_bytes(key_bytes.as_slice().into())
        .context("Failed to parse DICE alias private key")?;
    let signature: Signature = signing_key.sign(report_data);
    Ok(STANDARD.encode(signature.to_bytes()))
}

#[derive(Debug, Default)]
pub struct NvidiaDpuAttester {}

#[async_trait::async_trait]
impl Attester for NvidiaDpuAttester {
    /// Collect attestation evidence from the DPU device.
    ///
    /// The `report_data` parameter is used as a nonce to bind the evidence
    /// to a specific attestation session, preventing replay attacks.
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<TeeEvidence> {
        // Reject oversize nonce; pad shorter input with zeros
        if report_data.len() > NVIDIA_DPU_NONCE_SIZE {
            bail!("report_data exceeds maximum size of {} bytes", NVIDIA_DPU_NONCE_SIZE);
        }
        report_data.resize(NVIDIA_DPU_NONCE_SIZE, 0); // pad with zeros if shorter

        // Collect evidence from sysfs-exposed DICE attestation attributes.
        // BF3 exposes DICE certs via InfiniBand sysfs, not a chardev.
        let evidence = self.collect_evidence_from_sysfs(&report_data)?;

        serde_json::to_value(&evidence).context("Failed to serialize NVIDIA DPU evidence")
    }
}

impl NvidiaDpuAttester {
    /// Collect evidence from sysfs-exposed DICE attestation attributes.
    ///
    /// BlueField-3 exposes DICE certificates and measurements via the
    /// InfiniBand device sysfs path under `device/attestation/`.
    fn collect_evidence_from_sysfs(&self, report_data: &[u8]) -> Result<NvidiaDpuEvidence> {
        // Read DICE certificates from sysfs
        let alias_cert = std::fs::read(format!("{}/alias_cert", ATTESTATION_BASE_PATH))
            .context("failed to read alias cert")?;

        let device_id_cert = std::fs::read(format!("{}/device_id_cert", ATTESTATION_BASE_PATH))
            .context("failed to read device_id cert")?;

        // Read measurements if available
        let measurements_path = format!("{}/measurements", ATTESTATION_BASE_PATH);
        let measurements = if std::path::Path::new(&measurements_path).exists() {
            let measurement_bytes = std::fs::read(&measurements_path).unwrap_or_default();
            if measurement_bytes.len() % 48 != 0 {
                bail!("measurement buffer length {} is not a multiple of 48", measurement_bytes.len());
            }
            let entry_size = 1 + 48; // layer(u8) + SHA-384 digest
            measurement_bytes.chunks_exact(entry_size)
                .map(|chunk| NvidiaDpuMeasurement {
                    layer: chunk[0],
                    digest: chunk[1..49].try_into().expect("chunk is exactly 49 bytes"),
                })
                .collect()
        } else {
            Vec::new()
        };

        let report_data_signature = sign_report_data(report_data)?;

        Ok(NvidiaDpuEvidence {
            version: 1,
            devices: vec![DpuDeviceEvidence {
                architecture: "bluefield3".to_string(),
                alias_cert,
                device_id_cert,
                measurements,
                report_data_signature,
            }],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nvidia_dpu_evidence_serialize_deserialize_roundtrip() {
        let evidence = NvidiaDpuEvidence {
            version: 1,
            devices: vec![DpuDeviceEvidence {
                architecture: "bluefield3".to_string(),
                alias_cert: vec![1, 2, 3, 4],
                device_id_cert: vec![5, 6, 7, 8],
                measurements: vec![
                    NvidiaDpuMeasurement {
                        layer: 0,
                        digest: [0u8; 48], // SHA-384
                    },
                    NvidiaDpuMeasurement {
                        layer: 1,
                        digest: [1u8; 48],
                    },
                ],
                report_data_signature: "dGVzdF9zaWduYXR1cmU=".to_string(),
            }],
        };

        // Serialize to JSON string
        let json_str = serde_json::to_string(&evidence).unwrap();

        // Deserialize back
        let parsed: NvidiaDpuEvidence = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.devices.len(), 1);
        let device = &parsed.devices[0];
        assert_eq!(device.architecture, "bluefield3");
        assert_eq!(device.alias_cert, vec![1, 2, 3, 4]);
        assert_eq!(device.device_id_cert, vec![5, 6, 7, 8]);
        assert_eq!(device.measurements.len(), 2);
        assert_eq!(device.measurements[0].layer, 0);
        assert_eq!(device.measurements[0].digest.len(), 48);
        assert_eq!(device.measurements[1].layer, 1);
        assert_eq!(device.report_data_signature, "dGVzdF9zaWduYXR1cmU=");

        // Also verify serde_json::Value roundtrip
        let value = serde_json::to_value(&parsed).unwrap();
        let parsed2: NvidiaDpuEvidence = serde_json::from_value(value).unwrap();
        assert_eq!(parsed2.devices[0].alias_cert, device.alias_cert);
        assert_eq!(parsed2.devices[0].report_data_signature, device.report_data_signature);
    }

    #[test]
    fn test_detect_platform_no_device() {
        // On CI/dev machines without actual NVIDIA DPU hardware, detection should
        // return false gracefully without panicking.
        let result = detect_platform();
        // We just verify it doesn't panic
        let _ = result;
    }

    #[tokio::test]
    async fn test_get_evidence_no_hardware() {
        // Without NVIDIA DPU hardware, get_evidence should fail because
        // the DICE alias private key is not available (signature is mandatory).
        let attester = NvidiaDpuAttester::default();
        let report_data = vec![0u8; 32];

        let result = attester.get_evidence(report_data).await;
        // On machines without DPU hardware, this should error due to missing key
        assert!(result.is_err());
    }
}
