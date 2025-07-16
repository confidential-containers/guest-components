// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attester, TeeEvidence};
use anyhow::*;
use log::debug;
use pv::{
    misc,
    request::BootHdrTags,
    uv::{AttestationCmd, ConfigUid, UvDevice},
};
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use std::fs;

const DIGEST_FILE: &str = "/run/peerpod/initdata.digest";

pub fn detect_platform() -> bool {
    misc::pv_guest_bit_set()
}

#[repr(C)]
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct SeAttestationRequest {
    #[serde_as(as = "Base64")]
    request_blob: Vec<u8>,
    measurement_size: u32,
    additional_size: u32,
    #[serde_as(as = "Base64")]
    encr_measurement_key: Vec<u8>,
    #[serde_as(as = "Base64")]
    encr_request_nonce: Vec<u8>,
    #[serde_as(as = "Base64")]
    image_hdr_tags: BootHdrTags,
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
        } = request;
        let mut user_data = vec![0];
        if fs::metadata(DIGEST_FILE).is_ok() {
            user_data = fs::read(DIGEST_FILE)?;
        }
        let mut uvc: AttestationCmd = AttestationCmd::new_request(
            request_blob.into(),
            Some(user_data.to_vec()),
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
            user_data,
            cuid: *cuid,
            encr_measurement_key,
            encr_request_nonce,
            image_hdr_tags,
        };

        debug!("response json: {response:#?}");
        Ok(serde_json::to_value(&response)?)
    }
}
