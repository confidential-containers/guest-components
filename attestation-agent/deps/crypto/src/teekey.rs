// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Implementations of the TeeKey

use anyhow::*;
use kbs_types::TeePubKey;
use rsa::{PaddingScheme, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha384};

const RSA_PUBKEY_LENGTH: usize = 2048;
const NEW_PADDING: fn() -> PaddingScheme = PaddingScheme::new_pkcs1v15_encrypt;

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
        let k_mod =
            base64::encode_config(self.public_key.n().to_bytes_be(), base64::URL_SAFE_NO_PAD);
        let k_exp =
            base64::encode_config(self.public_key.e().to_bytes_be(), base64::URL_SAFE_NO_PAD);

        Ok(TeePubKey {
            kty: RSA_KEY_TYPE.to_string(),
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
