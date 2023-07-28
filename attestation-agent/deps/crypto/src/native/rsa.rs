// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use openssl::{
    pkey::Private,
    rsa::{Padding, Rsa},
};

use crate::PaddingMode;

#[derive(Debug, Clone)]
pub struct RSAKeyPair {
    private_key: Rsa<Private>,
}

impl RSAKeyPair {
    pub fn new() -> Result<RSAKeyPair> {
        let private_key = Rsa::generate(2048)?;
        Ok(Self { private_key })
    }

    pub fn decrypt(&self, mode: PaddingMode, cipher_text: Vec<u8>) -> Result<Vec<u8>> {
        let mut plaintext = Vec::new();
        match mode {
            PaddingMode::OAEP => self
                .private_key
                .private_decrypt(&cipher_text, &mut plaintext, Padding::PKCS1_OAEP)
                .map_err(|e| anyhow!("RSA key decrypt OAEP failed: {:?}", e))?,
            PaddingMode::PKCS1v15 => self
                .private_key
                .private_decrypt(&cipher_text, &mut plaintext, Padding::PKCS1)
                .map_err(|e| anyhow!("RSA key pkcs1v15 decrypt failed: {:?}", e))?,
        };
        Ok(plaintext)
    }

    pub fn n(&self) -> Vec<u8> {
        self.private_key.n().to_vec()
    }

    pub fn e(&self) -> Vec<u8> {
        self.private_key.e().to_vec()
    }
}
