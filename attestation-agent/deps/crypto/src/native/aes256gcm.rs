// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This mod implements aes-256-gcm encryption & decryption.

use anyhow::*;
use openssl::symm::Cipher;

const TAG_LENGTH: usize = 16;

pub fn decrypt_with_aad(
    key: &[u8],
    encrypted_data: &[u8],
    iv: &[u8],
    aad: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_256_gcm();

    openssl::symm::decrypt_aead(cipher, key, Some(iv), aad, encrypted_data, tag)
        .map_err(|e| anyhow!("{e:?}"))
}

pub fn decrypt(key: &[u8], encrypted_data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_256_gcm();
    if encrypted_data.len() < TAG_LENGTH {
        bail!("Illegal length of ciphertext");
    }

    let (data, tag) = encrypted_data.split_at(encrypted_data.len() - TAG_LENGTH);
    openssl::symm::decrypt_aead(cipher, key, Some(iv), &[], data, tag)
        .map_err(|e| anyhow!(e.to_string()))
}

pub fn encrypt(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_256_gcm();
    let mut tag = [0u8; TAG_LENGTH];
    let mut ciphertext = openssl::symm::encrypt_aead(cipher, key, Some(iv), &[], data, &mut tag)
        .map_err(|e| anyhow!(e.to_string()))?;
    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{decrypt, encrypt};

    #[rstest]
    #[case(b"0123456789abcdefghijklmnopqrstuv", b"plaintext1", b"unique nonce")]
    #[case(b"hijklmnopqrstuv0123456789abcdefg", b"plaintext2", b"unique2nonce")]
    fn en_decrypt(#[case] key: &[u8], #[case] plaintext: &[u8], #[case] iv: &[u8]) {
        let ciphertext = encrypt(key, plaintext, iv).expect("encryption failed");
        let plaintext_de = decrypt(key, &ciphertext, iv).expect("decryption failed");
        assert_eq!(plaintext, plaintext_de);
    }
}
