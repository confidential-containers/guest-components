// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Implementations of the TeeKey

use anyhow::*;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    pkcs8::LineEnding,
    traits::PublicKeyParts,
    Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use zeroize::Zeroizing;

use crate::rsa::{PaddingMode, RSA_PUBKEY_LENGTH};

#[derive(Debug, Clone)]
pub struct RSAKeyPair {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl RSAKeyPair {
    pub fn new() -> Result<RSAKeyPair> {
        let mut rng = rand::thread_rng();

        let private_key = RsaPrivateKey::new(&mut rng, RSA_PUBKEY_LENGTH)?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(RSAKeyPair {
            private_key,
            public_key,
        })
    }

    pub fn decrypt(&self, mode: PaddingMode, cipher_text: Vec<u8>) -> Result<Vec<u8>> {
        match mode {
            PaddingMode::OAEP => self
                .private_key
                .decrypt(Oaep::new::<sha2::Sha256>(), &cipher_text)
                .map_err(|e| anyhow!("RSA key decrypt OAEP failed: {:?}", e)),
            PaddingMode::PKCS1v15 => self
                .private_key
                .decrypt(Pkcs1v15Encrypt, &cipher_text)
                .map_err(|e| anyhow!("RSA key pkcs1v15 decrypt failed: {:?}", e)),
        }
    }

    pub fn n(&self) -> Vec<u8> {
        self.public_key.n().to_bytes_be()
    }

    pub fn e(&self) -> Vec<u8> {
        self.private_key.e().to_bytes_be()
    }

    pub fn to_pkcs1_pem(&self) -> Result<Zeroizing<String>> {
        let res = self.private_key.to_pkcs1_pem(LineEnding::default())?;
        Ok(res)
    }

    pub fn from_pkcs1_pem(pem: &str) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs1_pem(pem)?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            private_key,
            public_key,
        })
    }
}
