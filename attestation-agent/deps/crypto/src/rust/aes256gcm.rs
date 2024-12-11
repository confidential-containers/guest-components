// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This mod implements aes-256-gcm encryption & decryption.
use aes_gcm::{aead::Aead, AeadInPlace, Aes256Gcm, Key, KeyInit, Nonce};
use anyhow::*;

pub fn decrypt_with_aad(
    key: &[u8],
    encrypted_data: &[u8],
    iv: &[u8],
    aad: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    let decrypting_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(decrypting_key);
    let nonce = Nonce::from_slice(iv);
    let mut plaintext = encrypted_data.to_vec();
    cipher
        .decrypt_in_place_detached(nonce, aad, &mut plaintext, tag.into())
        .map_err(|e| anyhow!("aes-256-gcm decrypt failed: {:?}", e))?;

    Ok(plaintext)
}

pub fn decrypt(key: &[u8], encrypted_data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let decrypting_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(decrypting_key);
    let nonce = Nonce::from_slice(iv);
    let plain_text = cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|e| anyhow!("aes-256-gcm decrypt failed: {:?}", e))?;

    Ok(plain_text)
}

pub fn encrypt(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
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
    #[case(b"0123456789abcdefghijklmnopqrstuv", b"plaintext1", b"unique nonce")]
    #[case(b"hijklmnopqrstuv0123456789abcdefg", b"plaintext2", b"unique2nonce")]
    fn en_decrypt(#[case] key: &[u8], #[case] plaintext: &[u8], #[case] iv: &[u8]) {
        let ciphertext = encrypt(key, plaintext, iv).expect("encryption failed");
        let plaintext_de = decrypt(key, &ciphertext, iv).expect("decryption failed");
        assert_eq!(plaintext, plaintext_de);
    }
}
