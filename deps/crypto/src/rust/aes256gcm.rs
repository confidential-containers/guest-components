// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This mod implements aes-256-gcm encryption & decryption.

use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use anyhow::*;

pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let decrypting_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(decrypting_key);
    let nonce = Nonce::from_slice(iv);
    let plain_text = cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|e| anyhow!("aes-256-gcm decrypt failed: {:?}", e))?;

    Ok(plain_text)
}
