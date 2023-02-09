// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This mod implements aes-256-ctr decryption.

use anyhow::*;

#[cfg(all(feature = "rust-crypto", not(feature = "openssl")))]
pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aes::Aes256;
    use ctr::{
        cipher::{KeyIvInit, StreamCipher},
        Ctr128BE,
    };

    let mut decryptor = Ctr128BE::<Aes256>::new(key.into(), iv.into());
    let mut buf = Vec::new();
    buf.resize(encrypted_data.len(), b' ');
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

#[cfg(all(feature = "rust-crypto", feature = "openssl"))]
#[cfg(test)]
mod tests {
    use ctr::{
        cipher::{KeyIvInit, StreamCipher},
        Ctr128BE,
    };

    #[test]
    fn compatible_with_openssl() {
        use aes_gcm::aes::Aes256;

        let plaintext = b"plaintext message";
        let key = [0x42; 32];
        let iv = [0x24; 16];
        let mut cipher = Ctr128BE::<Aes256>::new(&key.into(), &iv.into());
        let mut cipher_text = Vec::new();
        cipher_text.resize(plaintext.len(), b' ');
        cipher
            .apply_keystream_b2b(plaintext, &mut cipher_text)
            .expect("encryption failed");

        let decrypted = super::decrypt(&cipher_text, &key, &iv).expect("decrypt failed");
        assert_eq!(decrypted, plaintext);
    }
}
