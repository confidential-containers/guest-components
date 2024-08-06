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

pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let encrypting_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(encrypting_key);
    let nonce = Nonce::from_slice(iv);
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| anyhow!("aes-256-gcm encrypt failed: {:?}", e))?;

    Ok(ciphertext)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{decrypt, encrypt};

    #[rstest]
    #[case(b"plaintext1", b"0123456789abcdefghijklmnopqrstuv", b"unique nonce")]
    #[case(b"plaintext2", b"hijklmnopqrstuv0123456789abcdefg", b"unique2nonce")]
    fn en_decrypt(#[case] plaintext: &[u8], #[case] key: &[u8], #[case] iv: &[u8]) {
        let ciphertext = encrypt(plaintext, key, iv).expect("encryption failed");
        let plaintext_de = decrypt(&ciphertext, key, iv).expect("decryption failed");
        assert_eq!(plaintext, plaintext_de);
    }
}
