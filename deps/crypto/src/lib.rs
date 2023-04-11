// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate strum;

use std::str::FromStr;

use anyhow::*;
use kbs_types::TeePubKey;
use rsa::{PaddingScheme, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha384};
use zeroize::Zeroizing;

mod aes256ctr;
mod aes256gcm;

const RSA_PUBKEY_LENGTH: usize = 2048;
const NEW_PADDING: fn() -> PaddingScheme = PaddingScheme::new_pkcs1v15_encrypt;

pub const RSA_ALGORITHM: &str = "RSA1_5";
pub const AES_256_GCM_ALGORITHM: &str = "A256GCM";

/// Supported WrapType, s.t. encryption algorithm using to encrypt the
/// [PLBCO](https://github.com/confidential-containers/attestation-agent/blob/main/docs/IMPLEMENTATION.md#encryption-and-decryption-of-container-image).
/// TODO: Support more kinds of en/decryption schemes.
#[derive(EnumString, AsRefStr)]
pub enum WrapType {
    /// The serialized name follows 5.2.6 section
    /// <https://www.rfc-editor.org/rfc/inline-errata/rfc7518.html>
    #[strum(serialize = "A256GCM")]
    Aes256Gcm,

    /// This type is not recommended as it is not AEAD.
    #[strum(serialize = "A256CTR")]
    Aes256Ctr,
}

type DecryptorFunc = Box<dyn Fn(&[u8], &[u8], &[u8]) -> Result<Vec<u8>>>;

impl From<WrapType> for DecryptorFunc {
    fn from(wt: WrapType) -> Self {
        match wt {
            WrapType::Aes256Gcm => Box::new(aes256gcm::decrypt),
            WrapType::Aes256Ctr => Box::new(aes256ctr::decrypt),
        }
    }
}

// The key inside TEE to decrypt confidential data.
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

    // Export TEE public key as specific structure.
    pub fn export_pubkey(&self) -> Result<TeePubKey> {
        let k_mod = base64::encode(self.public_key.n().to_bytes_be());
        let k_exp = base64::encode(self.public_key.e().to_bytes_be());

        Ok(TeePubKey {
            alg: RSA_ALGORITHM.to_string(),
            k_mod,
            k_exp,
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

// Returns a base64 of the sha384 of all chunks.
pub fn hash_chunks(chunks: Vec<Vec<u8>>) -> String {
    let mut hasher = Sha384::new();

    for chunk in chunks.iter() {
        hasher.update(chunk);
    }

    let res = hasher.finalize();

    base64::encode(res)
}

pub fn decrypt(
    key: Zeroizing<Vec<u8>>,
    ciphertext: Vec<u8>,
    iv: Vec<u8>,
    wrap_type: &str,
) -> Result<Vec<u8>> {
    let wrap_type = WrapType::from_str(wrap_type).context(format!(
        "Unsupported wrap type {wrap_type} when decrypt image layer",
    ))?;

    let decryptor: DecryptorFunc = wrap_type.into();
    let plaintext = decryptor(&ciphertext, &key, &iv)?;

    Ok(plaintext)
}
