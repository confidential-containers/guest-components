// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This mod implements aes-256-ctr encryption & decryption.

use aes_gcm::aes::Aes256;
use anyhow::*;
use ctr::{
    cipher::{KeyIvInit, StreamCipher},
    Ctr128BE,
};

pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let mut decryptor = Ctr128BE::<Aes256>::new(key.into(), iv.into());
    let mut buf = Vec::new();
    buf.resize(encrypted_data.len(), b' ');
    decryptor
        .apply_keystream_b2b(encrypted_data, &mut buf)
        .map_err(|e| anyhow!("aes-256-ctr decrypt failed: {:?}", e))?;
    Ok(buf)
}
