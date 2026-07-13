// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{utils::validate_and_pad_data, Attester, TeeEvidence};
use anyhow::*;
use pv::{
    misc,
    request::BootHdrTags,
    uv::{AttestationCmd, ConfigUid, UvDevice},
};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use tracing::debug;

/// The size for SE attestation report data (SHA-512 digest size in bytes).
/// Only the first `SE_REPORT_DATA_SIZE` bytes of the `runtime_data_digest` field
/// from `SeAttestationRequest` are used in the attestation command.
const SE_REPORT_DATA_SIZE: usize = 64;

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

        let runtime_digest = validate_and_pad_data(runtime_digest, SE_REPORT_DATA_SIZE)?;

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
    use rstest::{fixture, rstest};

    // SHA-512 sized mock digest reused across multiple tests
    const MOCK_RUNTIME_DIGEST: [u8; 64] = [0xBB; 64];

    // ---------------------------------------------------------------------------
    // Fixtures — shared test data built once and injected by rstest
    // ---------------------------------------------------------------------------

    /// Non-zero BootHdrTags used wherever a real boot header is not needed.
    /// Distinct, non-zero byte patterns in every field ensure that a serde
    /// round-trip that accidentally zeroes any field is caught by an assert_eq.
    #[fixture]
    fn dummy_tags() -> BootHdrTags {
        BootHdrTags::new([0x11u8; 64], [0x22u8; 64], [0x33u8; 64], [0x44u8; 16])
    }

    /// A valid `SeAttestationRequest` with a caller-supplied digest.
    fn make_request(runtime_data_digest: Option<Vec<u8>>) -> SeAttestationRequest {
        SeAttestationRequest {
            request_blob: vec![0u8; 32],
            measurement_size: 64,
            additional_size: 32,
            encr_measurement_key: vec![0u8; 32],
            encr_request_nonce: vec![0u8; 16],
            image_hdr_tags: BootHdrTags::new([0u8; 64], [0u8; 64], [0u8; 64], [0u8; 16]),
            runtime_data_digest,
        }
    }

    /// A canonical `SeAttestationResponse` for serde-only tests.
    /// cuid uses a non-zero pattern so that a round-trip that accidentally
    /// drops or zeroes the field is caught by the assert_eq checks below.
    #[fixture]
    fn dummy_response(dummy_tags: BootHdrTags) -> SeAttestationResponse {
        SeAttestationResponse {
            measurement: vec![0x01; 64],
            additional_data: vec![0x02; 32],
            user_data: vec![0x03; 64],
            cuid: [0xAAu8; 16],
            encr_measurement_key: vec![0x04; 32],
            encr_request_nonce: vec![0x05; 16],
            image_hdr_tags: dummy_tags,
        }
    }

    /// Pre-parsed JSON `Value` of `dummy_response` — built once, shared across
    /// all `test_response_binary_fields_are_base64_strings` cases via fixture.
    #[fixture]
    fn response_json_value(dummy_response: SeAttestationResponse) -> serde_json::Value {
        serde_json::from_str(&serde_json::to_string(&dummy_response).unwrap()).unwrap()
    }

    // ---------------------------------------------------------------------------
    // SE_REPORT_DATA_SIZE constant
    // ---------------------------------------------------------------------------

    #[test]
    fn test_se_report_data_size_is_sha512_length() {
        // Must equal 64 (SHA-512 byte length). A silent change breaks the
        // attestation-command contract with the UV firmware.
        assert_eq!(SE_REPORT_DATA_SIZE, 64);
    }

    // ---------------------------------------------------------------------------
    // UserData::to_bytes
    // Contract: returns the exact stored bytes, nothing added or removed.
    // ---------------------------------------------------------------------------

    #[rstest]
    #[case::empty(b"")]
    #[case::single_byte(&[0x42])]
    #[case::all_bytes(&(0u8..=255).collect::<Vec<u8>>())]
    #[case::production_digest(&MOCK_RUNTIME_DIGEST)]
    fn test_user_data_to_bytes(#[case] digest: &[u8]) {
        let user_data = UserData {
            runtime_data_digest: digest.to_vec(),
        };
        assert_eq!(user_data.to_bytes(), digest);
    }

    // ---------------------------------------------------------------------------
    // validate_and_pad_data — success path
    //
    // Contract: output length == expected_size, original bytes are at [..input_len],
    //           all appended bytes are 0x00.
    //
    // Cases cover: zero-sized target, under-full inputs at every interesting
    // boundary, exact match, and the all-byte-values correctness check.
    // ---------------------------------------------------------------------------

    #[rstest]
    #[case::zero_target_empty_input(vec![],                            0)]
    #[case::empty_padded_to_64(vec![],                                 SE_REPORT_DATA_SIZE)]
    #[case::one_byte_padded(vec![0xAA],                                SE_REPORT_DATA_SIZE)]
    #[case::four_bytes_padded(vec![0xAA, 0xBB, 0xCC, 0xDD],           SE_REPORT_DATA_SIZE)]
    #[case::sha256_size_padded(vec![0xFF; 32],                         SE_REPORT_DATA_SIZE)]
    #[case::boundary_minus_one(vec![0x42; SE_REPORT_DATA_SIZE-1],      SE_REPORT_DATA_SIZE)]
    #[case::exact_match(vec![0xAA; SE_REPORT_DATA_SIZE],               SE_REPORT_DATA_SIZE)]
    #[case::all_byte_values_survive((0u8..=255).collect(),             512)]
    fn test_validate_and_pad_data_ok(#[case] input: Vec<u8>, #[case] expected_size: usize) {
        let original_len = input.len();
        let result = validate_and_pad_data(input.clone(), expected_size).unwrap();

        assert_eq!(
            result.len(),
            expected_size,
            "output length must equal expected_size"
        );
        assert_eq!(
            &result[..original_len],
            input.as_slice(),
            "original bytes must be preserved"
        );
        assert!(
            result[original_len..].iter().all(|&b| b == 0),
            "all padding bytes must be 0x00"
        );
    }

    // ---------------------------------------------------------------------------
    // validate_and_pad_data — error path
    //
    // Contract: any input longer than expected_size returns Err containing
    // "too large" and the actual byte count.
    // ---------------------------------------------------------------------------

    #[rstest]
    #[case::any_byte_into_zero_size(vec![0x01],                        0)]
    #[case::boundary_plus_one(vec![0x42; SE_REPORT_DATA_SIZE+1],       SE_REPORT_DATA_SIZE)]
    #[case::well_above_limit(vec![0xFF; 100],                          SE_REPORT_DATA_SIZE)]
    fn test_validate_and_pad_data_err(#[case] input: Vec<u8>, #[case] expected_size: usize) {
        let input_len = input.len();
        let err = validate_and_pad_data(input, expected_size)
            .unwrap_err()
            .to_string();
        assert!(err.contains("too large"), "expected 'too large' in: {err}");
        assert!(
            err.contains(&input_len.to_string()),
            "expected actual length {input_len} in: {err}"
        );
    }

    // ---------------------------------------------------------------------------
    // SeAttestationRequest serialization
    // ---------------------------------------------------------------------------

    #[test]
    fn test_request_digest_some_survives_roundtrip() {
        // Some(digest): key must appear in JSON and bytes must round-trip exactly.
        let digest = MOCK_RUNTIME_DIGEST.to_vec();
        let json = serde_json::to_string(&make_request(Some(digest.clone()))).unwrap();
        assert!(
            json.contains("runtime_data_digest"),
            "key must be present when Some"
        );
        let parsed: SeAttestationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.runtime_data_digest, Some(digest));
    }

    #[test]
    fn test_request_digest_none_omitted_from_json() {
        // None: key must be absent entirely (skip_serializing_if) and round-trip
        // back to None.
        let json = serde_json::to_string(&make_request(None)).unwrap();
        assert!(
            !json.contains("runtime_data_digest"),
            "key must be absent when None, got: {json}"
        );
        let parsed: SeAttestationRequest = serde_json::from_str(&json).unwrap();
        assert!(parsed.runtime_data_digest.is_none());
    }

    #[rstest]
    fn test_request_all_fields_survive_roundtrip(dummy_tags: BootHdrTags) {
        // Every field must be faithfully preserved across a JSON round-trip,
        // not just runtime_data_digest.
        let request = SeAttestationRequest {
            request_blob: vec![0xDE, 0xAD, 0xBE, 0xEF],
            measurement_size: 128,
            additional_size: 64,
            encr_measurement_key: vec![0x11; 32],
            encr_request_nonce: vec![0x22; 16],
            image_hdr_tags: dummy_tags,
            runtime_data_digest: Some(vec![0x33; 48]),
        };
        let parsed: SeAttestationRequest =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();

        assert_eq!(parsed.request_blob, request.request_blob);
        assert_eq!(parsed.measurement_size, request.measurement_size);
        assert_eq!(parsed.additional_size, request.additional_size);
        assert_eq!(parsed.encr_measurement_key, request.encr_measurement_key);
        assert_eq!(parsed.encr_request_nonce, request.encr_request_nonce);
        // image_hdr_tags is serialised as Base64 bytes; assert the full struct
        // survives so that a removed/broken serde impl is immediately caught.
        assert_eq!(parsed.image_hdr_tags, request.image_hdr_tags);
        assert_eq!(parsed.runtime_data_digest, request.runtime_data_digest);
    }

    // ---------------------------------------------------------------------------
    // SeAttestationResponse serialization
    // ---------------------------------------------------------------------------

    #[rstest]
    fn test_response_all_fields_survive_roundtrip(dummy_response: SeAttestationResponse) {
        // All Base64 fields must round-trip without corruption.
        let parsed: SeAttestationResponse =
            serde_json::from_str(&serde_json::to_string(&dummy_response).unwrap()).unwrap();

        assert_eq!(parsed.measurement, dummy_response.measurement);
        assert_eq!(parsed.additional_data, dummy_response.additional_data);
        assert_eq!(parsed.user_data, dummy_response.user_data);
        // cuid is a [u8; 16] serialised as Base64; verify it is preserved so
        // that a broken serde impl does not silently produce all-zero output.
        assert_eq!(parsed.cuid, dummy_response.cuid);
        assert_eq!(
            parsed.encr_measurement_key,
            dummy_response.encr_measurement_key
        );
        assert_eq!(parsed.encr_request_nonce, dummy_response.encr_request_nonce);
        // image_hdr_tags is serialised as Base64 bytes; assert the full struct
        // survives so that a removed/broken serde impl is immediately caught.
        assert_eq!(parsed.image_hdr_tags, dummy_response.image_hdr_tags);
    }

    /// Binary fields must be JSON strings (base64), not integer arrays.
    /// Every field annotated with `#[serde_as(as = "Base64")]` on
    /// `SeAttestationResponse` must appear here — including cuid and
    /// image_hdr_tags which are fixed-size types rather than Vec<u8>.
    #[rstest]
    #[case::measurement("measurement")]
    #[case::additional_data("additional_data")]
    #[case::user_data("user_data")]
    #[case::cuid("cuid")]
    #[case::encr_measurement_key("encr_measurement_key")]
    #[case::encr_request_nonce("encr_request_nonce")]
    #[case::image_hdr_tags("image_hdr_tags")]
    fn test_response_binary_fields_are_base64_strings(
        #[case] field: &str,
        response_json_value: serde_json::Value,
    ) {
        assert!(
            response_json_value[field].is_string(),
            "field '{field}' must be a base64 string, got: {:?}",
            response_json_value[field]
        );
    }

    // ---------------------------------------------------------------------------
    // get_evidence — early-failure paths (no hardware required)
    //
    // These cases must all fail before reaching the UvDevice::open() call.
    // The optional `error_substr` is asserted against the error message when
    // the failure reason is deterministic.
    // ---------------------------------------------------------------------------

    #[rstest]
    #[case::invalid_json(b"not valid json {{{{".to_vec(),               None)]
    #[case::empty_input(vec![],                                         None)]
    #[case::missing_runtime_digest(
        serde_json::to_vec(&make_request(None)).unwrap(),
        Some("runtime_data_digest")
    )]
    #[case::digest_too_large(
        serde_json::to_vec(&make_request(Some(vec![0xAA; SE_REPORT_DATA_SIZE + 1]))).unwrap(),
        Some("too large")
    )]
    #[tokio::test]
    async fn test_get_evidence_early_failure(
        #[case] input: Vec<u8>,
        #[case] error_substr: Option<&str>,
    ) {
        let result = SeAttester::default().get_evidence(input).await;
        assert!(result.is_err());
        if let Some(substr) = error_substr {
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains(substr), "expected '{substr}' in: {msg}");
        }
    }

    // ---------------------------------------------------------------------------
    // SeAttester construction
    // ---------------------------------------------------------------------------

    #[test]
    fn test_se_attester_default_construction() {
        // Must not panic; guards against future fields with failing defaults.
        let _attester = SeAttester::default();
    }
}
