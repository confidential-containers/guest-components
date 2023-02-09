// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This mod implements aes-256-gcm decryption.

use anyhow::*;

#[cfg(all(feature = "rust-crypto", not(feature = "openssl")))]
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};

#[cfg(all(feature = "rust-crypto", not(feature = "openssl")))]
pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let decrypting_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(decrypting_key);
    let nonce = Nonce::from_slice(iv);
    let plain_text = cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|e| anyhow!("aes-256-gcm decrypt failed: {:?}", e))?;

    Ok(plain_text)
}

#[cfg(feature = "openssl")]
use openssl::symm::Cipher;

#[cfg(feature = "openssl")]
const TAG_LENGTH: usize = 16;

#[cfg(feature = "openssl")]
pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_256_gcm();
    if encrypted_data.len() < TAG_LENGTH {
        bail!("Illegal length of ciphertext");
    }

    let (data, tag) = encrypted_data.split_at(encrypted_data.len() - TAG_LENGTH);
    openssl::symm::decrypt_aead(cipher, key, Some(iv), &[], data, tag)
        .map_err(|e| anyhow!(e.to_string()))
}

#[cfg(all(feature = "rust-crypto", feature = "openssl"))]
#[cfg(test)]
mod tests {
    use aes_gcm::{
        aead::{Aead, OsRng},
        Aes256Gcm, KeyInit, Nonce,
    };

    #[test]
    fn compatible_with_openssl() {
        let plaintext = b"plaintext message";
        let key = Aes256Gcm::generate_key(&mut OsRng);
        let keyu8 = key.to_vec();
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .expect("encryption failed");

        let decrypted = super::decrypt(&ciphertext, &keyu8, &nonce).expect("decrypt failed");
        assert_eq!(decrypted, plaintext);
    }
}
