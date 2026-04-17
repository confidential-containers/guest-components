// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, TeeEvidence};
use anyhow::*;
use base64::{engine::general_purpose, Engine as _};
use pv::{
    misc,
    request::BootHdrTags,
    uv::{AttestationCmd, ConfigUid, UvDevice},
};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use std::fs;
use tracing::debug;

const DIGEST_FILE: &str = "/run/peerpod/initdata.digest";

/// Structured user data for IBM SEL attestation
/// Contains runtime and optional initdata digests
/// Concatenated and bound to the attestation measurement
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserData {
    #[serde_as(as = "Base64")]
    pub runtime_data_digest: Vec<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<Base64>")]
    pub initdata_digest: Option<Vec<u8>>,
}

impl UserData {
    /// Serialize to Base64-encoded bytes for attestation command:
    /// runtime_data_digest || initdata_digest (if present)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.runtime_data_digest);
        if let Some(ref digest) = self.initdata_digest {
            bytes.extend_from_slice(digest);
        }
        // Encode to Base64 to ensure UTF-8 compatibility
        general_purpose::STANDARD.encode(&bytes).into_bytes()
    }
}

pub fn detect_platform() -> bool {
    misc::pv_guest_bit_set()
}

#[repr(C)]
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct SeAttestationRequest {
    #[serde_as(as = "Base64")]
    pub request_blob: Vec<u8>,
    pub measurement_size: u32,
    pub additional_size: u32,
    #[serde_as(as = "Base64")]
    pub encr_measurement_key: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub encr_request_nonce: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub image_hdr_tags: BootHdrTags,
    /// Initdata digest to be used as user_data for baremetal
    /// This is computed from the initdata TOML by AttestationAgent
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<Base64>")]
    pub initdata_digest: Option<Vec<u8>>,
    /// Runtime data digest computed from the full JSON structure:
    /// (tee-pubkey, nonce, additional-evidence)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<Base64>")]
    pub runtime_data_digest: Option<Vec<u8>>,
}

#[repr(C)]
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct SeAttestationResponse {
    #[serde_as(as = "Base64")]
    measurement: Vec<u8>,
    #[serde_as(as = "Base64")]
    additional_data: Vec<u8>,
    #[serde_as(as = "Base64")]
    user_data: Vec<u8>,
    #[serde_as(as = "Base64")]
    cuid: ConfigUid,
    #[serde_as(as = "Base64")]
    encr_measurement_key: Vec<u8>,
    #[serde_as(as = "Base64")]
    encr_request_nonce: Vec<u8>,
    #[serde_as(as = "Base64")]
    image_hdr_tags: BootHdrTags,
}

#[derive(Debug, Default)]
pub struct SeAttester {}

#[async_trait::async_trait]
impl Attester for SeAttester {
    async fn get_evidence(&self, req: Vec<u8>) -> Result<TeeEvidence> {
        let request: SeAttestationRequest = serde_json::from_slice(&req)?;
        let SeAttestationRequest {
            request_blob,
            measurement_size,
            additional_size,
            encr_measurement_key,
            encr_request_nonce,
            image_hdr_tags,
            initdata_digest,
            runtime_data_digest,
        } = request;

        // Construct user_data with runtime_data_digest (required) and initdata_digest (optional)
        let runtime_digest =
            runtime_data_digest.ok_or_else(|| anyhow!("runtime_data_digest not provided"))?;

        debug!(
            "Using runtime_data_digest, length: {}, content: {:?}",
            runtime_digest.len(),
            runtime_digest
        );

        if runtime_digest.len() != 48 {
            bail!(
                "Invalid runtime_data_digest length: expected 48 bytes (SHA-384), got {}",
                runtime_digest.len()
            );
        }

        // Determine initdata_digest source:
        // 1. Try reading from DIGEST_FILE first (peer-pods)
        // 2. If initdata_digest is given in request, use it (baremetal)
        // 3. Otherwise, None
        let initdata = if fs::metadata(DIGEST_FILE).is_ok() {
            debug!("Reading initdata digest from file: {}", DIGEST_FILE);
            let digest = fs::read(DIGEST_FILE).context("Failed to read initdata digest file")?;
            debug!(
                "Reading initdata digest from file, length: {}, content: {:?}",
                digest.len(),
                digest
            );
            Some(digest)
        } else if let Some(digest) = initdata_digest {
            debug!(
                "Using initdata digest from request, length: {}, content: {:?}",
                digest.len(),
                digest
            );
            Some(digest)
        } else {
            debug!("No initdata source available");
            None
        };

        let user_data = UserData {
            runtime_data_digest: runtime_digest,
            initdata_digest: initdata,
        };

        let user_data_bytes = user_data.to_bytes();

        let mut uvc: AttestationCmd = AttestationCmd::new_request(
            request_blob.into(),
            Some(user_data_bytes.clone()),
            measurement_size,
            additional_size,
        )?;
        let uv = UvDevice::open()?;
        uv.send_cmd(&mut uvc)?;
        let cuid = uvc.cuid();
        let additional_data = uvc
            .additional_owned()
            .ok_or(anyhow!("Failed to get additinal data."))?;
        let response: SeAttestationResponse = SeAttestationResponse {
            measurement: uvc.measurement().to_vec(),
            additional_data,
            user_data: user_data_bytes,
            cuid: *cuid,
            encr_measurement_key,
            encr_request_nonce,
            image_hdr_tags,
        };

        debug!("response json: {response:#?}");
        Ok(serde_json::to_value(&response)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock runtime digest (SHA-384 size: 48 bytes) for tests
    // This simulates the digest computed from runtime data in production
    const MOCK_RUNTIME_DIGEST: [u8; 48] = [0xBB; 48];

    // Helper to create a dummy BootHdrTags for testing
    fn create_dummy_boot_hdr_tags() -> BootHdrTags {
        // BootHdrTags::new signature: (pld: [u8; 64], ald: [u8; 64], tld: [u8; 64], tag: [u8; 16])
        let pld = [0u8; 64];
        let ald = [0u8; 64];
        let tld = [0u8; 64];
        let tag = [0u8; 16];
        BootHdrTags::new(pld, ald, tld, tag)
    }

    #[tokio::test]
    async fn test_initdata_digest_injection() {
        // Create a mock initdata digest
        let expected_digest = vec![1, 2, 3, 4, 5, 6, 7, 8];

        let request = SeAttestationRequest {
            request_blob: vec![0; 32],
            measurement_size: 64,
            additional_size: 32,
            encr_measurement_key: vec![0; 32],
            encr_request_nonce: vec![0; 16],
            image_hdr_tags: create_dummy_boot_hdr_tags(),
            initdata_digest: Some(expected_digest.clone()),
            runtime_data_digest: Some(MOCK_RUNTIME_DIGEST.to_vec()),
        };

        // Serialize and deserialize (simulating the JSON flow in get_evidence)
        let request_json = serde_json::to_vec(&request).unwrap();
        let parsed: SeAttestationRequest = serde_json::from_slice(&request_json).unwrap();

        // Verify the digest is preserved through serialization
        assert!(parsed.initdata_digest.is_some());
        assert_eq!(parsed.initdata_digest.unwrap(), expected_digest);
    }

    #[tokio::test]
    async fn test_initdata_digest_none_when_not_provided() {
        // Test that initdata_digest can be None and is properly handled
        let request = SeAttestationRequest {
            request_blob: vec![0; 32],
            measurement_size: 64,
            additional_size: 32,
            encr_measurement_key: vec![0; 32],
            encr_request_nonce: vec![0; 16],
            image_hdr_tags: create_dummy_boot_hdr_tags(),
            initdata_digest: None,
            runtime_data_digest: Some(MOCK_RUNTIME_DIGEST.to_vec()),
        };

        let request_json = serde_json::to_vec(&request).unwrap();
        let parsed: SeAttestationRequest = serde_json::from_slice(&request_json).unwrap();

        assert!(parsed.initdata_digest.is_none());
    }

    #[tokio::test]
    async fn test_initdata_digest_with_various_sizes() {
        // Test with different digest sizes to ensure robustness
        let test_cases = vec![
            vec![],                       // Empty digest
            vec![0xAA],                   // Single byte
            vec![0xAA, 0xBB, 0xCC, 0xDD], // 4 bytes
            vec![0; 32],                  // 32 bytes (SHA-256 size)
            vec![0xFF; 64],               // 64 bytes (SHA-512 size)
        ];

        for expected_digest in test_cases {
            let request = SeAttestationRequest {
                request_blob: vec![0; 32],
                measurement_size: 64,
                additional_size: 32,
                encr_measurement_key: vec![0; 32],
                encr_request_nonce: vec![0; 16],
                image_hdr_tags: create_dummy_boot_hdr_tags(),
                initdata_digest: Some(expected_digest.clone()),
                runtime_data_digest: Some(MOCK_RUNTIME_DIGEST.to_vec()),
            };

            let request_json = serde_json::to_vec(&request).unwrap();
            let parsed: SeAttestationRequest = serde_json::from_slice(&request_json).unwrap();

            assert_eq!(parsed.initdata_digest, Some(expected_digest));
        }
    }

    #[tokio::test]
    async fn test_initdata_digest_base64_serialization() {
        // Verify that the digest is properly base64 encoded in JSON
        let digest = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let request = SeAttestationRequest {
            request_blob: vec![0; 32],
            measurement_size: 64,
            additional_size: 32,
            encr_measurement_key: vec![0; 32],
            encr_request_nonce: vec![0; 16],
            image_hdr_tags: create_dummy_boot_hdr_tags(),
            initdata_digest: Some(digest.clone()),
            runtime_data_digest: Some(MOCK_RUNTIME_DIGEST.to_vec()),
        };

        let request_json = serde_json::to_string(&request).unwrap();

        // Verify JSON contains base64-encoded digest
        assert!(request_json.contains("initdata_digest"));

        // Verify round-trip preserves the data
        let parsed: SeAttestationRequest = serde_json::from_str(&request_json).unwrap();
        assert_eq!(parsed.initdata_digest, Some(digest));
    }

    #[tokio::test]
    async fn test_runtime_data_digest_injection() {
        // Test that runtime_data_digest is properly handled
        let expected_runtime_digest = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

        let request = SeAttestationRequest {
            request_blob: vec![0; 32],
            measurement_size: 64,
            additional_size: 32,
            encr_measurement_key: vec![0; 32],
            encr_request_nonce: vec![0; 16],
            image_hdr_tags: create_dummy_boot_hdr_tags(),
            initdata_digest: None,
            runtime_data_digest: Some(expected_runtime_digest.clone()),
        };

        // Serialize and deserialize
        let request_json = serde_json::to_vec(&request).unwrap();
        let parsed: SeAttestationRequest = serde_json::from_slice(&request_json).unwrap();

        // Verify the digest is preserved
        assert!(parsed.runtime_data_digest.is_some());
        assert_eq!(parsed.runtime_data_digest.unwrap(), expected_runtime_digest);
    }

    #[tokio::test]
    async fn test_both_digests_present() {
        // Test that both initdata_digest and runtime_data_digest can coexist
        let initdata_digest = vec![0xAA; 32];
        let runtime_digest = vec![0xBB; 48];

        let request = SeAttestationRequest {
            request_blob: vec![0; 32],
            measurement_size: 64,
            additional_size: 32,
            encr_measurement_key: vec![0; 32],
            encr_request_nonce: vec![0; 16],
            image_hdr_tags: create_dummy_boot_hdr_tags(),
            initdata_digest: Some(initdata_digest.clone()),
            runtime_data_digest: Some(runtime_digest.clone()),
        };

        let request_json = serde_json::to_string(&request).unwrap();

        // Verify both fields are in JSON
        assert!(request_json.contains("initdata_digest"));
        assert!(request_json.contains("runtime_data_digest"));

        // Verify round-trip preserves both
        let parsed: SeAttestationRequest = serde_json::from_str(&request_json).unwrap();
        assert_eq!(parsed.initdata_digest, Some(initdata_digest));
        assert_eq!(parsed.runtime_data_digest, Some(runtime_digest));
    }

    #[tokio::test]
    async fn test_runtime_digest_not_provided_returns_error() {
        // Test that missing runtime_data_digest causes get_evidence to return an error
        let request = SeAttestationRequest {
            request_blob: vec![0; 32],
            measurement_size: 64,
            additional_size: 32,
            encr_measurement_key: vec![0; 32],
            encr_request_nonce: vec![0; 16],
            image_hdr_tags: create_dummy_boot_hdr_tags(),
            initdata_digest: Some(vec![0xAA; 32]),
            runtime_data_digest: None, // Missing runtime_data_digest
        };

        let request_json = serde_json::to_vec(&request).unwrap();

        // Note: Full integration test with get_evidence would require SE hardware/mock
        // requiring mocking UvDevice, so we verify the serialization behavior
        // In production, get_evidence would fail with "runtime_data_digest not provided"
        let parsed: SeAttestationRequest = serde_json::from_slice(&request_json).unwrap();

        // Verify that runtime_data_digest is None (which would trigger the error in get_evidence)
        assert!(parsed.runtime_data_digest.is_none());
    }
}
