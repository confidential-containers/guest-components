// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::KBS_URL_PREFIX;
use crate::kbc_modules::cc_kbc::kbs_protocol::message::Response;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use anyhow::*;
use rsa::pkcs8::EncodePublicKey;
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

const RSA_KEY_TYPE: &str = "RSA";
const RSA_ALGORITHM: &str = "RSA1_5";
const RSA_PUBKEY_LENGTH: usize = 2048;
const NEW_PADDING: fn() -> PaddingScheme = PaddingScheme::new_pkcs1v15_encrypt;

pub const AES_256_GCM_ALGORITHM: &str = "A256GCM";

// Image Encryption Annotation.
#[derive(Serialize, Deserialize)]
pub struct AnnotationPacket {
    // Key Resource ID (URL)
    // Format:
    // `cc_kbc://127.0.0.1:8080/test_repo/key/id_1`
    pub kid: String,
    // Encrypted key to unwrap (base64-encoded)
    pub wrapped_data: String,
    // Initialisation vector (base64-encoded)
    pub iv: String,
    // Wrap type to specify encryption algorithm and mode
    pub wrap_type: String,
}

impl AnnotationPacket {
    pub fn wrapped_data(&self) -> Result<Vec<u8>> {
        base64::decode(&self.wrapped_data)
            .map_err(|e| anyhow!("Failed to decode wrapped key: {}", e))
    }

    pub fn iv(&self) -> Result<Vec<u8>> {
        base64::decode(&self.iv)
            .map_err(|e| anyhow!("Failed to decode initialization vector: {}", e))
    }

    pub fn wrap_type(&self) -> &str {
        &self.wrap_type
    }

    pub fn kbc_name(&self) -> &str {
        self.kid.split("://").collect::<Vec<&str>>()[0]
    }

    pub fn key_url(&self) -> Result<String> {
        let kid_without_prefix = self.kid.split("://").collect::<Vec<&str>>()[1].to_string();
        let (kbs_addr, key_path) = kid_without_prefix
            .split_once('/')
            .ok_or(anyhow!("Invalid KID in AnnotationPacket"))?;

        // Now only support `http://` prefix.
        Ok(format!(
            "http://{kbs_addr}/{KBS_URL_PREFIX}/resource/{key_path}"
        ))
    }

    pub fn decrypt(&self, key: &[u8]) -> Result<Vec<u8>> {
        match self.wrap_type() {
            AES_256_GCM_ALGORITHM => aes_gcm_256_decrypt(&self.wrapped_data()?, key, &self.iv()?)
                .map_err(|e| anyhow!("Failed to decrypt annotation: {}", e)),
            _ => {
                bail!("Unsupported wrapped type in Annotation Packet")
            }
        }
    }
}

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
    pub k: String,
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
        AES_256_GCM_ALGORITHM => aes_gcm_256_decrypt(&ciphertext, &symkey, &iv)?,
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

pub fn aes_gcm_256_decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let decrypting_key = aes_gcm::Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(decrypting_key);
    let nonce = aes_gcm::Nonce::from_slice(iv);
    let plain_text = cipher
        .decrypt(nonce, encrypted_data.as_ref())
        .map_err(|_| anyhow!("A256GCM decrypt failed"))?;

    Ok(plain_text)
}
