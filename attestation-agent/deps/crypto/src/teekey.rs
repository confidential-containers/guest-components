// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Implementations of the TeeKey

use anyhow::*;
use base64::Engine;
use kbs_types::TeePubKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{
    traits::PublicKeyParts, PaddingScheme, Pkcs1v15Encrypt, PublicKeyParts, RsaPrivateKey,
    RsaPublicKey,
};
use sha2::{Digest, Sha384};

const RSA_PUBKEY_LENGTH: usize = 2048;

pub const RSA_KEY_TYPE: &str = "RSA";
pub const RSA_ALGORITHM: &str = "RSA1_5";
pub const AES_256_GCM_ALGORITHM: &str = "A256GCM";

/// The key inside TEE to decrypt confidential data.
#[derive(Debug, Clone)]
pub struct TeeKey {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl TeeKey {
    pub fn new() -> Result<TeeKey> {
        let mut rng = rand::thread_rng();

        let private_key = RsaPrivateKey::new(&mut rng, RSA_PUBKEY_LENGTH)?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(TeeKey {
            private_key,
            public_key,
        })
    }

    // Export TEE public key as JWK, as defined in RFC 7517.
    pub fn export_pubkey(&self) -> Result<TeePubKey> {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let k_mod = engine.encode(self.public_key.n().to_bytes_be());
        let k_exp = engine.encode(self.public_key.e().to_bytes_be());

        Ok(TeePubKey {
            kty: RSA_KEY_TYPE.to_string(),
            alg: RSA_ALGORITHM.to_string(),
            k_mod,
            k_exp,
        })
    }

    // Use TEE private key to decrypt cipher text.
    pub fn decrypt(&self, cipher_text: Vec<u8>) -> Result<Vec<u8>> {
        self.private_key
            .decrypt(Pkcs1v15Encrypt, &cipher_text)
            .map_err(|e| anyhow!("TEE RSA key decrypt failed: {:?}", e))
    }
}

// Returns a sha384 of all chunks.
pub fn hash_chunks(chunks: Vec<Vec<u8>>) -> Vec<u8> {
    let mut hasher = Sha384::new();

    for chunk in chunks.iter() {
        hasher.update(chunk);
    }

    hasher.finalize().to_vec()
}

// Convert PKCS#1 PEM public key to TeePubKey
pub fn pkcs1_pem_to_teepubkey(pem: String) -> Result<TeePubKey> {
    let public_key = RsaPublicKey::from_pkcs1_pem(&pem)?;
    let k_mod = base64::encode(public_key.n().to_bytes_be());
    let k_exp = base64::encode(public_key.e().to_bytes_be());
    let tee_pubkey = TeePubKey {
        kty: RSA_KEY_TYPE.to_string(),
        alg: RSA_ALGORITHM.to_string(),
        k_mod,
        k_exp,
    };
    Ok(tee_pubkey)
}
