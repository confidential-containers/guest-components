// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::*;

pub const HARDCODED_KEY: &'static [u8] = &[
    217, 155, 119, 5, 176, 186, 122, 22, 130, 149, 179, 163, 54, 114, 112, 176, 221, 155, 55, 27,
    245, 20, 202, 139, 155, 167, 240, 163, 55, 17, 218, 234,
];

pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let encryption_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(encryption_key);
    let nonce = Nonce::from_slice(iv);
    let encrypted_data = cipher
        .encrypt(nonce, data.as_ref())
        .map_err(|e| anyhow!("Decrypt failed: {:?}", e))?;

    Ok(encrypted_data)
}
