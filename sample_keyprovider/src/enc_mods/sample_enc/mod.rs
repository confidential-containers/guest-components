// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use rand::RngCore;

pub mod annotation;
pub mod crypto;

pub fn enc_optsdata_gen_anno(optsdata: &[u8], _params: Vec<String>) -> Result<String> {
    let mut iv: [u8; 12] = [0; 12];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    let encrypt_optsdata = crypto::encrypt(optsdata, crypto::HARDCODED_KEY, &iv)?;

    let annotation = annotation::AnnotationPacket {
        kid: "null".to_string(),
        wrapped_data: encrypt_optsdata,
        iv: iv.to_vec(),
        wrap_type: "aes-gcm".to_string(),
    };
    let anno_string = serde_json::to_string(&annotation)?;

    Ok(anno_string)
}
