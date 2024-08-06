// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This mod implements aes-256-ctr encryption & decryption.

use aes_gcm::aes::Aes256;
use anyhow::*;
use ctr::{
    cipher::{KeyIvInit, StreamCipher},
    Ctr128BE,
};

pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let mut decryptor = Ctr128BE::<Aes256>::new(key.into(), iv.into());
    let mut buf = Vec::new();
    buf.resize(encrypted_data.len(), b' ');
    decryptor
        .apply_keystream_b2b(encrypted_data, &mut buf)
        .map_err(|e| anyhow!("aes-256-ctr decrypt failed: {:?}", e))?;
    Ok(buf)
}

pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let mut encryptor = Ctr128BE::<Aes256>::new(key.into(), iv.into());
    let mut ciphertext = data.to_vec();
    encryptor.apply_keystream(&mut ciphertext);
    Ok(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt};
    use rstest::rstest;

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
