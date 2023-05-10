// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This mod implements aes-256-ctr encryption & decryption.

use anyhow::*;
use openssl::symm::Cipher;

pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_256_ctr();

    openssl::symm::decrypt(cipher, key, Some(iv), encrypted_data)
        .map_err(|e| anyhow!(e.to_string()))
}
