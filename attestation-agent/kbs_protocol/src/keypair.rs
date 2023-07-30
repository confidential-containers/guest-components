// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Context, Result};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crypto::{
    rsa::{PaddingMode, RSAKeyPair, RSA_KTY},
    WrapType,
};
use kbs_types::{Response, TeePubKey};
use serde::Deserialize;
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

        Ok(TeePubKey {
            alg: PaddingMode::PKCS1v15.as_ref().to_string(),
            k_mod,
            k_exp,
            kty: RSA_KTY.to_string(),
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
        // deserialize the jose header and check that the key type matches
        let protected: ProtectedHeader = serde_json::from_str(&response.protected)?;
        let padding_mode = PaddingMode::try_from(&protected.alg[..])
            .context("Unsupported padding mode for wrapped key")?;

        // unwrap the wrapped key
        let wrapped_symkey: Vec<u8> = URL_SAFE_NO_PAD.decode(&response.encrypted_key)?;
        let symkey = self.decrypt(padding_mode, wrapped_symkey)?;

        let iv = URL_SAFE_NO_PAD.decode(&response.iv)?;
        let ciphertext = URL_SAFE_NO_PAD.decode(&response.ciphertext)?;

        let plaintext = crypto::decrypt(Zeroizing::new(symkey), ciphertext, iv, protected.enc)?;

        Ok(plaintext)
    }
}

#[derive(Deserialize)]
struct ProtectedHeader {
    /// enryption algorithm for encrypted key
    alg: String,
    /// encryption algorithm for payload
    enc: WrapType,
}
