// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::kbc_modules::cc_kbc::kbs_protocol::message::Response;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use anyhow::*;
use rsa::pkcs8::EncodePublicKey;
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

const RSA_KEY_TYPE: &str = "RSA1_5";
const RSA_ALGORITHM: &str = "rsa-pkcs1v15";
const RSA_PUBKEY_LENGTH: usize = 2048;
const NEW_PADDING: fn() -> PaddingScheme = PaddingScheme::new_pkcs1v15_encrypt;

const AES_GCM_256_ALGORITHM: &str = "A256GCM";

// The key inside TEE to decrypt confidential data.
#[derive(Debug, Clone)]
pub struct TeeKey {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

// The struct that used to export the public key of TEE.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TeePubKey {
    kty: String,
    alg: String,
    k: String,
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
            kty: RSA_KEY_TYPE.to_string(),
            alg: RSA_ALGORITHM.to_string(),
            k: pubkey_pem_string,
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

#[derive(Serialize, Deserialize)]
struct ProtectedHeader {
    // enryption algorithm for encrypted key
    alg: String,
    // encryption algorithm for payload
    enc: String,
}

pub fn decrypt_response(response: &Response, tee_key: TeeKey) -> Result<Vec<u8>> {
    // deserialize the jose header and check that the key type matches
    let protected: ProtectedHeader = serde_json::from_str(&response.protected)?;
    if protected.alg != RSA_ALGORITHM {
        return Err(anyhow!("Algorithm mismatch for wrapped key."));
    }

    // unwrap the wrapped key
    let wrapped_symkey: Vec<u8> =
        base64::decode_config(&response.encrypted_key, base64::URL_SAFE_NO_PAD)?;
    let symkey: Vec<u8> = tee_key.decrypt(wrapped_symkey)?;

    let iv = base64::decode_config(&response.iv, base64::URL_SAFE_NO_PAD)?;
    let ciphertext = base64::decode_config(&response.ciphertext, base64::URL_SAFE_NO_PAD)?;

    let plaintext = match protected.enc.as_str() {
        AES_GCM_256_ALGORITHM => {
            let decryption_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&symkey);
            let aes_gcm_cipher = Aes256Gcm::new(decryption_key);

            let nonce = aes_gcm::Nonce::from_slice(&iv);

            aes_gcm_cipher
                .decrypt(nonce, ciphertext.as_ref())
                .map_err(|e| anyhow!("AES_GCM_256_ALGORITHM: {:?}", e))?
        }
        _ => {
            return Err(anyhow!("Unsupported algorithm: {}", protected.enc.clone()));
        }
    };

    Ok(plaintext)
}

// Returns a base64 of the sha384 of all chunks.
pub fn hash_chunks(chunks: Vec<Vec<u8>>) -> String {
    let mut hasher = Sha384::new();

    for chunk in chunks.iter() {
        hasher.update(chunk);
    }

    let res = hasher.finalize();

    base64::encode(res)
}
