// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Context, Result};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crypto::rsa::{PaddingMode, RSAKeyPair};
use kbs_types::{Response, TeePubKey};
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub struct TeeKeyPair {
    keypair: RSAKeyPair,
}

impl TeeKeyPair {
    pub fn new() -> Result<Self> {
        Ok(Self {
            keypair: RSAKeyPair::new()?,
        })
    }

    /// Export TEE public key as specific structure.
    pub fn export_pubkey(&self) -> Result<TeePubKey> {
        let k_mod = URL_SAFE_NO_PAD.encode(self.keypair.n());
        let k_exp = URL_SAFE_NO_PAD.encode(self.keypair.e());

        Ok(TeePubKey::RSA {
            alg: PaddingMode::PKCS1v15.as_ref().to_string(),
            k_mod,
            k_exp,
        })
    }

    #[inline]
    pub fn decrypt(&self, mode: PaddingMode, cipher_text: Vec<u8>) -> Result<Vec<u8>> {
        self.keypair.decrypt(mode, cipher_text)
    }

    #[inline]
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self> {
        let keypair = RSAKeyPair::from_pkcs1_pem(pem)?;
        Ok(Self { keypair })
    }

    #[inline]
    pub fn to_pkcs1_pem(&self) -> Result<Zeroizing<String>> {
        self.keypair.to_pkcs1_pem()
    }

    pub fn decrypt_response(&self, response: Response) -> Result<Vec<u8>> {
        let padding_mode = PaddingMode::try_from(&response.protected.alg[..])
            .context("Unsupported padding mode for wrapped key")?;

        // unwrap the wrapped key
        let symkey = self.decrypt(padding_mode, response.encrypted_key)?;

        let aad = response.protected.generate_aad()?;
        let plaintext = crypto::aes256gcm_decrypt(
            Zeroizing::new(symkey),
            response.ciphertext,
            response.iv,
            aad,
            response.tag,
        )?;

        Ok(plaintext)
    }
}
