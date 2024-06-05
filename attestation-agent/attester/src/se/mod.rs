// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
use log::debug;
use pv::{
    request::BootHdrTags,
    uv::{AttestationCmd, ConfigUid, UvDevice},
};
use serde::{Deserialize, Serialize};
use serde_json;
use serde_with::{base64::Base64, serde_as};

pub fn detect_platform() -> bool {
    // run always on s390x machine
    let v = std::fs::read("/sys/firmware/uv/prot_virt_guest").unwrap_or_else(|_| vec![0]);
    let v: u8 = String::from_utf8_lossy(&v[..1]).parse().unwrap_or(0);
    v == 1
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserData {
    #[serde_as(as = "Base64")]
    image_btph: Vec<u8>,
}

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

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    async fn get_evidence(&self, req: Vec<u8>) -> Result<String> {
        // req is serialized SeAttestationRequest String bytes
        // TODO, calculate optional userdata based on the boot partition etc.
        let image_btph = "optional check";
        let userdata = UserData {
            image_btph: image_btph.into(),
        };

        debug!("userdata json: {userdata:#?}");
        // req is serialized SeAttestationRequest String bytes
        let request: SeAttestationRequest = serde_json::from_slice(req)?;
        let user_data = serde_json::to_vec(&userdata)?;
        let mut uvc: AttestationCmd = AttestationCmd::new_request(
            request.request_blob.clone().into(),
            Some(user_data.to_vec()),
            request.measurement_size,
            request.additional_size,
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
            encr_measurement_key: request.encr_measurement_key,
            encr_request_nonce: request.encr_request_nonce,
            image_hdr_tags: request.image_hdr_tags,
        };

        debug!("response json: {response:#?}");
        Ok(serde_json::to_string(&response)?)
    }
}
