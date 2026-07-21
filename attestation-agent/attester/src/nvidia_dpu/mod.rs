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
use p384::ecdsa::signature::Signer;
use p384::ecdsa::{Signature, SigningKey};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

/// PCI vendor ID for Mellanox/NVIDIA networking devices.
const NVIDIA_MLX_VENDOR_ID: &str = "15b3";
/// PCI device IDs that identify BlueField-3 (as opposed to ConnectX-7 or other NICs).
/// - a2dc: BF3 integrated NIC function
/// - a2da: BF3 SoC PCI bridge
const BF3_DEVICE_IDS: &[&str] = &["a2dc", "a2da"];

const PCI_DEVICES_PATH: &str = "/sys/bus/pci/devices";
const NVIDIA_DPU_NONCE_SIZE: usize = 64;

/// Architecture identifier for NVIDIA BlueField-3 DPU.
const ARCHITECTURE_BF3: &str = "bluefield3";

/// DICE alias private key exposed by the BlueField platform attestation subsystem.
///
/// Requires: `mlnx_bf_attestation` kernel module (part of MLNX_OFED >= 24.10 / DOCA >= 2.8).
/// This runs on the BF3 ARM SoC Linux (the "DPU OS"), not the x86 host.
///
/// Security model: key availability to the attested OS is inherent to DICE —
/// any firmware change rotates the CDI, producing a different key pair.
/// Future: PSC hardware signing (sign-without-extract) for defense-in-depth.
const ALIAS_PRIVATE_KEY_PATH: &str = "/sys/kernel/security/tee/dice/alias_private_key";

/// Base path for DPU attestation attributes exposed via InfiniBand sysfs.
///
/// Requires: `mlx5_core` kernel driver with attestation support
/// (MLNX_OFED >= 24.10 or DOCA >= 2.8 BFB image with attestation feature enabled).
/// The standard DOCA production BFB images include this by default since DOCA 2.8.
///
/// Reference: <https://docs.nvidia.com/networking/display/dpunicattestation>
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
    /// DER-encoded X.509 DICE Alias certificate (leaf, signed by DeviceID key).
    /// Read as raw bytes from sysfs; the verifier parses the X.509 structure.
    #[serde_as(as = "Base64")]
    pub alias_cert: Vec<u8>,
    /// DER-encoded X.509 DICE DeviceID certificate (signed by manufacturer Root CA).
    /// Read as raw bytes from sysfs; the verifier parses the X.509 structure.
    #[serde_as(as = "Base64")]
    pub device_id_cert: Vec<u8>,
    /// ECDSA P-384 signature of report_data using DICE alias private key
    #[serde_as(as = "Base64")]
    pub report_data_signature: Vec<u8>,
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

        if vendor == NVIDIA_MLX_VENDOR_ID && BF3_DEVICE_IDS.iter().any(|id| device == *id) {
            return true;
        }
    }

    false
}

/// Sign report_data with DICE alias private key for freshness binding.
/// Returns the raw signature bytes (DER-encoded ECDSA P-384).
/// Returns error if the key is unavailable (unsigned evidence is not acceptable).
fn sign_report_data(report_data: &[u8]) -> Result<Vec<u8>> {
    // DICE alias private key from NVIDIA attestation subsystem layout.
    // Reference: https://docs.nvidia.com/networking/display/dpunicattestation
    let key_bytes = std::fs::read(ALIAS_PRIVATE_KEY_PATH)
        .context("DICE alias private key not available - cannot produce signed evidence")?;
    if key_bytes.len() != 48 {
        bail!(
            "signing key must be exactly 48 bytes (P-384), got {}",
            key_bytes.len()
        );
    }
    let signing_key = SigningKey::from_bytes(key_bytes.as_slice().into())
        .context("Failed to parse DICE alias private key")?;
    let signature: Signature = signing_key.sign(report_data);
    Ok(signature.to_bytes().to_vec())
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
        // Pad or truncate to fixed nonce register size (ECDSA signs arbitrary length internally)
        report_data.resize(NVIDIA_DPU_NONCE_SIZE, 0);

        // Collect evidence from sysfs-exposed DICE attestation attributes.
        // BF3 exposes DICE certs via InfiniBand sysfs, not a chardev.
        let evidence = self.collect_evidence_from_sysfs(&report_data)?;

        serde_json::to_value(&evidence).context("Failed to serialize NVIDIA DPU evidence")
    }
}

impl NvidiaDpuAttester {
    /// Collect evidence from sysfs-exposed DICE attestation attributes.
    ///
    /// BlueField-3 exposes DER-encoded X.509 DICE certificates via the
    /// InfiniBand device sysfs path under `device/attestation/`.
    /// The raw DER bytes are passed through as-is; parsing is done by the verifier.
    fn collect_evidence_from_sysfs(&self, report_data: &[u8]) -> Result<NvidiaDpuEvidence> {
        // Read DER-encoded X.509 DICE certificates from sysfs
        let alias_cert = std::fs::read(format!("{}/alias_cert", ATTESTATION_BASE_PATH))
            .context("failed to read alias cert")?;

        let device_id_cert = std::fs::read(format!("{}/device_id_cert", ATTESTATION_BASE_PATH))
            .context("failed to read device_id cert")?;

        let report_data_signature = sign_report_data(report_data)?;

        Ok(NvidiaDpuEvidence {
            version: 1,
            devices: vec![DpuDeviceEvidence {
                architecture: ARCHITECTURE_BF3.to_string(),
                alias_cert,
                device_id_cert,
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
                architecture: ARCHITECTURE_BF3.to_string(),
                alias_cert: vec![1, 2, 3, 4],
                device_id_cert: vec![5, 6, 7, 8],
                report_data_signature: b"test_signature".to_vec(),
            }],
        };

        // Serialize to JSON string
        let json_str = serde_json::to_string(&evidence).unwrap();

        // Deserialize back
        let parsed: NvidiaDpuEvidence = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.devices.len(), 1);
        let device = &parsed.devices[0];
        assert_eq!(device.architecture, ARCHITECTURE_BF3);
        assert_eq!(device.alias_cert, vec![1, 2, 3, 4]);
        assert_eq!(device.device_id_cert, vec![5, 6, 7, 8]);
        assert_eq!(device.report_data_signature, b"test_signature".to_vec());

        // Also verify serde_json::Value roundtrip
        let value = serde_json::to_value(&parsed).unwrap();
        let parsed2: NvidiaDpuEvidence = serde_json::from_value(value).unwrap();
        assert_eq!(parsed2.devices[0].alias_cert, device.alias_cert);
        assert_eq!(
            parsed2.devices[0].report_data_signature,
            device.report_data_signature
        );
    }

    #[test]
    fn test_detect_platform_no_device() {
        // On CI/dev machines without actual NVIDIA DPU hardware, detection should
        // return false gracefully without panicking.
        let result = detect_platform();
        // We just verify it doesn't panic
        let _ = result;
    }
}
