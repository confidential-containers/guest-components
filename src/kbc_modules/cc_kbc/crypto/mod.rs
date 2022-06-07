// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::Aes256Gcm;
use anyhow::*;
use rsa::pkcs8::EncodePublicKey;
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

const RSA_ALGORITHM: &str = "rsa-pkcs1v15";
const RSA_PUBKEY_LENGTH: usize = 2048;
const NEW_PADDING: fn() -> PaddingScheme = PaddingScheme::new_pkcs1v15_encrypt;

const AES_GCM_256_ALGORITHM: &str = "aes-gcm-256";

// The key inside TEE to decrypt confidential data.
#[derive(Debug, Clone)]
pub struct TeeKey {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

// The struct that used to export the public key of TEE.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TeePubKey {
    algorithm: String,
    #[serde(rename = "pubkey-length")]
    pubkey_length: usize,

    // public key string in PEM format.
    pubkey: String,
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

    // Export TEE public key as specific structure.
    pub fn export_pubkey(&self) -> Result<TeePubKey> {
        let pem_line_ending = rsa::pkcs1::LineEnding::default();
        let pubkey_pem_string = self.public_key.to_public_key_pem(pem_line_ending)?;

        Ok(TeePubKey {
            algorithm: RSA_ALGORITHM.to_string(),
            pubkey_length: RSA_PUBKEY_LENGTH,
            pubkey: pubkey_pem_string,
        })
    }

    // Use TEE private key to decrypt cipher text.
    pub fn decrypt(&self, cipher_text: Vec<u8>) -> Result<Vec<u8>> {
        let padding = NEW_PADDING();

        self.private_key
            .decrypt(padding, &cipher_text)
            .map_err(|e| anyhow!("TEE RSA key decrypt failed: {:?}", e))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CryptoAnnotation {
    algorithm: String,

    // The input to a cryptographic primitive being used to provide the initial state.
    // Base64 encoded.
    // If don't need, left blank.
    #[serde(rename = "initialization-vector")]
    initialization_vector: String,

    // The symmetric key encrypted by TEE's public key.
    // This symmetric key is used to encrypt API output by KBS.
    // Base64 encoded.
    #[serde(rename = "enc-symkey")]
    enc_symkey: String,
}

impl CryptoAnnotation {
    // Use the TEE private key to unwrap the encrypted symmetric key,
    // then use the symmetric key to decrypt cipher text.
    #[allow(unused_assignments)]
    pub fn decrypt(&self, tee_key: TeeKey, cipher_text: Vec<u8>) -> Result<Vec<u8>> {
        let wrapped_symkey: Vec<u8> = base64::decode(self.enc_symkey.clone())?;
        let symkey: Vec<u8> = tee_key.decrypt(wrapped_symkey)?;

        // Support various algorithm.
        let plain_text = match self.algorithm.as_str() {
            AES_GCM_256_ALGORITHM => {
                let decrypting_key = aes_gcm::Key::from_slice(&symkey);
                let aes_gcm_cipher = Aes256Gcm::new(decrypting_key);

                let iv_decoded = base64::decode(self.initialization_vector.clone())?;
                let nonce = aes_gcm::Nonce::from_slice(&iv_decoded);

                aes_gcm_cipher
                    .decrypt(nonce, cipher_text.as_ref())
                    .map_err(|e| anyhow!("AES_GCM_256_ALGORITHM: {:?}", e))?
            }
            _ => {
                return Err(anyhow!("Unsupported algorithm: {}", self.algorithm.clone()));
            }
        };

        Ok(plain_text)
    }
}

// Returns a base64 of the sha384 of all chunks.
pub fn hash_chunks(chunks: Vec<Vec<u8>>) -> String {
    let mut hasher = Sha384::new();

    for chunk in chunks.iter() {
        hasher.update(&chunk);
    }

    let res = hasher.finalize();

    base64::encode(res)
}
