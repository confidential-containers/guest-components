// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, TeeEvidence};
use anyhow::*;
use pv::{
    misc,
    request::BootHdrTags,
    uv::{AttestationCmd, ConfigUid, UvDevice},
};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use tracing::debug;

const RUNTIME_DIGEST_SIZE: usize = 48; // SHA-384 digest size in bytes

/// Structured user data for IBM SEL attestation
/// Currently, only contains runtime data digest bound to the attestation measurement
/// This could be extended in the future to include additional fields
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserData {
    #[serde_as(as = "Base64")]
    pub runtime_data_digest: Vec<u8>,
}

impl UserData {
    /// Return runtime_data_digest as raw bytes for attestation command
    pub fn to_bytes(&self) -> Vec<u8> {
        self.runtime_data_digest.clone()
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
            runtime_data_digest,
        } = request;

        // Construct user_data with runtime_data_digest
        let runtime_digest =
            runtime_data_digest.ok_or_else(|| anyhow!("runtime_data_digest not provided"))?;

        debug!(
            "Using runtime_data_digest, length: {}, content: {:?}",
            runtime_digest.len(),
            runtime_digest
        );

        let runtime_digest = match runtime_digest.len() {
            len if len > RUNTIME_DIGEST_SIZE => {
                bail!(
                    "Invalid runtime_data_digest length: expected {} bytes (SHA-384), got {} (too large)",
                    RUNTIME_DIGEST_SIZE,
                    len
                );
            }
            len if len < RUNTIME_DIGEST_SIZE => {
                debug!(
                    "Padding runtime_data_digest from {} to {} bytes with zeros",
                    len, RUNTIME_DIGEST_SIZE
                );
                let mut padded = runtime_digest;
                padded.resize(RUNTIME_DIGEST_SIZE, 0);
                padded
            }
            _ => runtime_digest, // Exact match, use as-is
        };

        let user_data = UserData {
            runtime_data_digest: runtime_digest,
        };

        let user_data_bytes = user_data.to_bytes();

        // user_data is used to produce the measurement (HMAC),
        // meaning if the data is different, the measurement will be different.
        // See: https://www.ibm.com/docs/en/linux-on-systems?topic=commands-pvattest
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
    async fn test_runtime_data_digest_serialization() {
        // Test that runtime_data_digest is properly serialized and deserialized
        let expected_digest = MOCK_RUNTIME_DIGEST.to_vec();

        let request = SeAttestationRequest {
            request_blob: vec![0; 32],
            measurement_size: 64,
            additional_size: 32,
            encr_measurement_key: vec![0; 32],
            encr_request_nonce: vec![0; 16],
            image_hdr_tags: create_dummy_boot_hdr_tags(),
            runtime_data_digest: Some(expected_digest.clone()),
        };

        // Serialize and deserialize (simulating the JSON flow in get_evidence)
        let request_json = serde_json::to_vec(&request).unwrap();
        let parsed: SeAttestationRequest = serde_json::from_slice(&request_json).unwrap();

        // Verify the digest is preserved through serialization
        assert!(parsed.runtime_data_digest.is_some());
        assert_eq!(parsed.runtime_data_digest.unwrap(), expected_digest);
    }

    #[tokio::test]
    async fn test_runtime_data_digest_none_when_not_provided() {
        // Test that runtime_data_digest can be None and is properly handled
        let request = SeAttestationRequest {
            request_blob: vec![0; 32],
            measurement_size: 64,
            additional_size: 32,
            encr_measurement_key: vec![0; 32],
            encr_request_nonce: vec![0; 16],
            image_hdr_tags: create_dummy_boot_hdr_tags(),
            runtime_data_digest: None,
        };

        let request_json = serde_json::to_vec(&request).unwrap();
        let parsed: SeAttestationRequest = serde_json::from_slice(&request_json).unwrap();

        assert!(parsed.runtime_data_digest.is_none());
    }

    #[tokio::test]
    async fn test_runtime_data_digest_with_various_sizes() {
        // Helper function that mimics the validation/padding logic from lines 110-129
        fn process_runtime_digest(runtime_digest: Vec<u8>) -> Result<Vec<u8>> {
            match runtime_digest.len() {
                len if len > RUNTIME_DIGEST_SIZE => {
                    bail!(
                        "Invalid runtime_data_digest length: expected {} bytes (SHA-384), got {} (too large)",
                        RUNTIME_DIGEST_SIZE,
                        len
                    )
                }
                len if len < RUNTIME_DIGEST_SIZE => {
                    let mut padded = runtime_digest;
                    padded.resize(RUNTIME_DIGEST_SIZE, 0);
                    Ok(padded)
                }
                _ => Ok(runtime_digest), // Exact match, use as-is
            }
        }

        // Case 1: Exact size (48 bytes) - should use as-is
        let exact_digest = vec![0xAA; RUNTIME_DIGEST_SIZE];
        let result = process_runtime_digest(exact_digest.clone()).unwrap();
        assert_eq!(result.len(), RUNTIME_DIGEST_SIZE);
        assert_eq!(result, exact_digest);

        // Case 2: Too small (< 48 bytes) - should be padded with zeros
        let small_test_cases = vec![
            (vec![], 0),                       // Empty digest
            (vec![0xAA], 1),                   // Single byte
            (vec![0xAA, 0xBB, 0xCC, 0xDD], 4), // 4 bytes
            (vec![0xFF; 32], 32),              // 32 bytes (SHA-256 size)
            (vec![0x11; 47], 47),              // 47 bytes (just under limit)
        ];

        for (small_digest, original_len) in small_test_cases {
            let result = process_runtime_digest(small_digest.clone()).unwrap();

            // Verify result is padded to 48 bytes
            assert_eq!(result.len(), RUNTIME_DIGEST_SIZE);

            // Verify original data is preserved at the beginning
            assert_eq!(&result[..original_len], &small_digest[..]);

            // Verify zeros are padded at the end
            for i in original_len..RUNTIME_DIGEST_SIZE {
                assert_eq!(result[i], 0, "Byte at index {} should be 0 (padded)", i);
            }
        }

        // Case 3: Too large (> 48 bytes) - should return error
        let large_test_cases = vec![
            (vec![0xFF; 49], 49),   // 49 bytes (just over limit)
            (vec![0xFF; 64], 64),   // 64 bytes (SHA-512 size)
            (vec![0xFF; 100], 100), // 100 bytes (way over limit)
        ];

        for (large_digest, len) in large_test_cases {
            let result = process_runtime_digest(large_digest);

            // Verify error is returned
            assert!(
                result.is_err(),
                "Digest of size {} should produce an error",
                len
            );

            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("too large"),
                "Error should mention 'too large'"
            );
            assert!(
                err_msg.contains(&len.to_string()),
                "Error should mention length {}",
                len
            );
        }
    }

    #[tokio::test]
    async fn test_runtime_data_digest_base64_serialization() {
        // Verify that the digest is properly base64 encoded in JSON
        let digest = MOCK_RUNTIME_DIGEST.to_vec();

        let request = SeAttestationRequest {
            request_blob: vec![0; 32],
            measurement_size: 64,
            additional_size: 32,
            encr_measurement_key: vec![0; 32],
            encr_request_nonce: vec![0; 16],
            image_hdr_tags: create_dummy_boot_hdr_tags(),
            runtime_data_digest: Some(digest.clone()),
        };

        let request_json = serde_json::to_string(&request).unwrap();

        // Verify JSON contains base64-encoded digest
        assert!(request_json.contains("runtime_data_digest"));

        // Verify round-trip preserves the data
        let parsed: SeAttestationRequest = serde_json::from_str(&request_json).unwrap();
        assert_eq!(parsed.runtime_data_digest, Some(digest));
    }

    #[tokio::test]
    async fn test_user_data_to_bytes() {
        // Test that UserData correctly returns runtime_data_digest as raw bytes
        let runtime_digest = MOCK_RUNTIME_DIGEST.to_vec();
        let user_data = UserData {
            runtime_data_digest: runtime_digest.clone(),
        };

        let bytes = user_data.to_bytes();

        // Verify it returns raw bytes directly
        assert_eq!(bytes, runtime_digest);
    }
}
