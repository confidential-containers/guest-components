// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This mod implements aes-256-ctr decryption.

use anyhow::*;

#[cfg(feature = "rust-crypto")]
use aes_gcm::aes::Aes256;
#[cfg(feature = "rust-crypto")]
use ctr::{
    cipher::{KeyIvInit, StreamCipher},
    Ctr128BE,
};

#[cfg(feature = "rust-crypto")]
pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let mut decryptor = Ctr128BE::<Aes256>::new(key.into(), iv.into());
    let mut buf = Vec::new();
    decryptor
        .apply_keystream_b2b(encrypted_data, &mut buf)
        .map_err(|e| anyhow!("aes-256-ctr decrypt failed: {:?}", e))?;
    Ok(buf)
}

#[cfg(feature = "openssl")]
use openssl::symm::Cipher;

#[cfg(feature = "openssl")]
pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_256_ctr();

    openssl::symm::decrypt(cipher, key, Some(iv), encrypted_data)
        .map_err(|e| anyhow!(e.to_string()))
}
