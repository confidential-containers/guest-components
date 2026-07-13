// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use openssl::{
    pkey::Private,
    rsa::{Padding, Rsa},
};
use zeroize::Zeroizing;

use crate::rsa::{PaddingMode, RSA_PUBKEY_LENGTH};

#[derive(Debug, Clone)]
pub struct RSAKeyPair {
    private_key: Rsa<Private>,
}

impl RSAKeyPair {
    pub fn new() -> Result<RSAKeyPair> {
        let private_key = Rsa::generate(RSA_PUBKEY_LENGTH as u32)?;
        Ok(Self { private_key })
    }

    pub fn decrypt(&self, mode: PaddingMode, cipher_text: Vec<u8>) -> Result<Vec<u8>> {
        let mut plaintext = [0; RSA_PUBKEY_LENGTH];
        let decrypted_size = match mode {
            // TODO: Update to OAEP + Sha256 API
            // Now the OAEP decrypter provided by openssl API is an ffi binding for
            // `RSA_public_encrypt` in openssl
            // Due to <https://docs.openssl.org/master/man3/RSA_public_encrypt/#synopsis>
            // this api assumes the digest algorithm is SHA-1.
            // This is not compatible with the implementation of the KBS side who uses
            // sha256.
            //
            // Let's mark this as a TODO because we are using EC now. Even if we want
            // to use RSA OAEP, the rust version of this crate can work normally.
            PaddingMode::OAEP => self
                .private_key
                .private_decrypt(&cipher_text, &mut plaintext, Padding::PKCS1_OAEP)
                .map_err(|e| anyhow!("RSA key decrypt OAEP failed: {:?}", e))?,
            #[allow(deprecated)]
            PaddingMode::PKCS1v15 => self
                .private_key
                .private_decrypt(&cipher_text, &mut plaintext, Padding::PKCS1)
                .map_err(|e| anyhow!("RSA key pkcs1v15 decrypt failed: {:?}", e))?,
        };

        Ok(plaintext[..decrypted_size].to_vec())
    }

    pub fn n(&self) -> Vec<u8> {
        self.private_key.n().to_vec()
    }

    pub fn e(&self) -> Vec<u8> {
        self.private_key.e().to_vec()
    }

    pub fn to_pkcs1_pem(&self) -> Result<Zeroizing<String>> {
        let res = self.private_key.private_key_to_pem()?;
        let pem = String::from_utf8(res)?;
        Ok(Zeroizing::new(pem))
    }

    pub fn from_pkcs1_pem(pem: &str) -> Result<Self> {
        let private_key = Rsa::<Private>::private_key_from_pem(pem.as_bytes())?;

        Ok(Self { private_key })
    }
}
