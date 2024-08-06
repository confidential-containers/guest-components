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

pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_256_ctr();
    let ciphertext =
        openssl::symm::encrypt(cipher, key, Some(iv), data).map_err(|e| anyhow!(e.to_string()))?;
    Ok(ciphertext)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{decrypt, encrypt};

    #[rstest]
    #[case(
        b"plaintext1",
        b"0123456789abcdefghijklmnopqrstuv",
        b"16bytes ivlength"
    )]
    #[case(
        b"plaintext2",
        b"hijklmnopqrstuv0123456789abcdefg",
        b"16bytes ivlength"
    )]
    fn en_decrypt(#[case] plaintext: &[u8], #[case] key: &[u8], #[case] iv: &[u8]) {
        let ciphertext = encrypt(plaintext, key, iv).expect("encryption failed");
        let plaintext_de = decrypt(&ciphertext, key, iv).expect("decryption failed");
        assert_eq!(plaintext, plaintext_de);
    }
}
