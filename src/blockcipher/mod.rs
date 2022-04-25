// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::Read;

use anyhow::{anyhow, Result};
use base64_serde::base64_serde_type;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

pub mod aes_ctr;
use aes_ctr::AESCTRBlockCipher;

/// LayerCipherType is the ciphertype as specified in the layer metadata
pub type LayerCipherType = String;

/// TODO: Should be obtained from OCI spec once included
pub const AES256CTR: &str = "AES_256_CTR_HMAC_SHA256";

base64_serde_type!(Base64Vec, base64::STANDARD);

fn base64_hashmap_s<S>(value: &HashMap<String, Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let b64_encoded: HashMap<_, _> = value
        .iter()
        .map(|(k, v)| (k.clone(), base64::encode_config(v, base64::STANDARD)))
        .collect();
    b64_encoded.serialize(serializer)
}

fn base64_hashmap_d<'de, D>(deserializer: D) -> Result<HashMap<String, Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let b64_encoded: HashMap<String, String> = serde::Deserialize::deserialize(deserializer)?;
    b64_encoded
        .iter()
        .map(|(k, v)| -> Result<(String, Vec<u8>), D::Error> {
            Ok((
                k.clone(),
                base64::decode_config(v, base64::STANDARD).map_err(de::Error::custom)?,
            ))
        })
        .collect()
}

/// PrivateLayerBlockCipherOptions includes the information required to encrypt/decrypt
/// an image layer which are sensitive and should not be in plaintext
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct PrivateLayerBlockCipherOptions {
    /// symmetric_key represents the symmetric key used for encryption/decryption
    /// This field should be populated by encrypt/decrypt calls
    #[serde(rename = "symkey", with = "Base64Vec")]
    pub symmetric_key: Vec<u8>,

    /// digest is the digest of the original data for verification.
    /// This is NOT populated by encrypt/decrypt calls
    pub digest: String,

    /// cipher_options contains the cipher metadata used for encryption/decryption
    /// This field should be populated by encrypt/decrypt calls
    #[serde(
        rename = "cipheroptions",
        serialize_with = "base64_hashmap_s",
        deserialize_with = "base64_hashmap_d"
    )]
    pub cipher_options: HashMap<String, Vec<u8>>,
}

/// PublicLayerBlockCipherOptions includes the information required to encrypt/decrypt
/// an image layer which are public and can be deduplicated in plaintext across multiple
/// recipients
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct PublicLayerBlockCipherOptions {
    /// cipher_type denotes the cipher type according to the list of OCI suppported
    #[serde(rename = "cipher")]
    pub cipher_type: LayerCipherType,

    /// hmac contains the hmac string to help verify encryption
    #[serde(with = "Base64Vec")]
    pub hmac: Vec<u8>,

    /// cipher_options contains the cipher metadata used for encryption/decryption
    /// This field should be populated by encrypt/decrypt calls
    #[serde(
        rename = "cipheroptions",
        serialize_with = "base64_hashmap_s",
        deserialize_with = "base64_hashmap_d"
    )]
    pub cipher_options: HashMap<String, Vec<u8>>,
}

/// LayerBlockCipherOptions contains the public and private LayerBlockCipherOptions
/// required to encrypt/decrypt an image
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct LayerBlockCipherOptions {
    pub public: PublicLayerBlockCipherOptions,
    pub private: PrivateLayerBlockCipherOptions,
}

impl LayerBlockCipherOptions {
    /// get_opt returns the value of the cipher option if the option exists
    pub fn get_opt(&self, key: String) -> Option<Vec<u8>> {
        match self.public.cipher_options.get(&key) {
            Some(value) => Some(value.to_vec()),
            None => self
                .private
                .cipher_options
                .get(&key)
                .map(|value| value.to_vec()),
        }
    }
}

/// LayerBlockCipher defined the interface for setting up encrypt/decrypt functionality
/// with the input data for a specific algorithm
pub trait LayerBlockCipher<R: Read> {
    /// generate_key creates a symmetric key
    fn generate_key(&self) -> Result<Vec<u8>>;

    /// encrypt takes in layer data and required LayerBlockCipherOptions to initialize encrypt process
    fn encrypt(&mut self, input: R, opts: &mut LayerBlockCipherOptions) -> Result<()>;

    /// decrypt takes in layer ciphertext data and required LayerBlockCipherOptions to initialize decrypt process
    fn decrypt(&mut self, input: R, opts: &mut LayerBlockCipherOptions) -> Result<()>;
}

pub trait Finalizer {
    /// finalized_lbco update LayerBlockCipherOptions after finished encrypt operation
    fn finalized_lbco(&self, opts: &mut LayerBlockCipherOptions) -> Result<()>;
}

/// LayerBlockCipherHandler is the handler for encrypt/decrypt for layers
pub struct LayerBlockCipherHandler<R: Read> {
    pub aes_ctr_block_cipher: Option<AESCTRBlockCipher<R>>,
}

impl<R: Read> LayerBlockCipherHandler<R> {
    /// Create a LayerBlockCipherHandler with default aes ctr block cipher
    pub fn new() -> Result<LayerBlockCipherHandler<R>> {
        let aes_ctr_block_cipher = AESCTRBlockCipher::new(256)?;
        let handler = LayerBlockCipherHandler {
            aes_ctr_block_cipher: Some(aes_ctr_block_cipher),
        };

        Ok(handler)
    }

    /// encrypt is the handler for the layer encryption routine
    pub fn encrypt(
        &mut self,
        plain_data_reader: R,
        typ: &str,
        opts: &mut LayerBlockCipherOptions,
    ) -> Result<()> {
        if typ != AES256CTR {
            return Err(anyhow!("unsupported cipher type {}", typ));
        }

        match &mut self.aes_ctr_block_cipher {
            Some(block_cipher) => {
                let sk = block_cipher.generate_key()?;
                opts.private.symmetric_key = sk;
                opts.public.cipher_type = AES256CTR.to_string();

                block_cipher.encrypt(plain_data_reader, opts)?;
                Ok(())
            }
            None => Err(anyhow!("uninitialized cipher")),
        }
    }

    /// decrypt is the handler for the layer decryption routine
    pub fn decrypt(
        &mut self,
        enc_data_reader: R,
        opts: &mut LayerBlockCipherOptions,
    ) -> Result<()> {
        let typ = &opts.public.cipher_type;
        if typ != AES256CTR {
            return Err(anyhow!("unsupported cipher type {}", typ));
        }

        match &mut self.aes_ctr_block_cipher {
            Some(block_cipher) => {
                block_cipher.decrypt(enc_data_reader, opts)?;
                Ok(())
            }
            None => Err(anyhow!("uninitialized cipher")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layer_block_cipher_handler() {
        let layer_data: Vec<u8> = b"this is some data".to_vec();

        let mut lbco = LayerBlockCipherOptions::default();
        let mut lbch = LayerBlockCipherHandler::new().unwrap();
        assert!(lbch
            .encrypt(layer_data.as_slice(), AES256CTR, &mut lbco)
            .is_ok());

        let mut encrypted_data: Vec<u8> = Vec::new();
        assert!(lbch
            .encrypt(layer_data.as_slice(), AES256CTR, &mut lbco)
            .is_ok());
        let mut encryptor = lbch.aes_ctr_block_cipher.unwrap();
        assert!(encryptor.read_to_end(&mut encrypted_data).is_ok());
        assert!(encryptor.finalized_lbco(&mut lbco).is_ok());

        let serialized_json = serde_json::to_string(&lbco).unwrap();

        // Decrypt with valid key
        let mut lbch = LayerBlockCipherHandler::new().unwrap();
        let mut lbco: LayerBlockCipherOptions =
            serde_json::from_str(&serialized_json).unwrap_or_default();

        assert!(lbch.decrypt(encrypted_data.as_slice(), &mut lbco).is_ok());
        let mut decryptor = lbch.aes_ctr_block_cipher.unwrap();
        let mut plaintxt_data: Vec<u8> = Vec::new();
        assert!(decryptor.read_to_end(&mut plaintxt_data).is_ok());

        // Decrypted data should equal to original data
        assert_eq!(layer_data, plaintxt_data);

        // Decrypt with invalid key
        let mut lbch = LayerBlockCipherHandler::new().unwrap();
        lbco.private.symmetric_key = vec![0; 32];
        assert!(lbch.decrypt(encrypted_data.as_slice(), &mut lbco).is_ok());
        let mut decryptor = lbch.aes_ctr_block_cipher.unwrap();
        let mut plaintxt_data: Vec<u8> = Vec::new();
        assert!(decryptor.read_to_end(&mut plaintxt_data).is_err());
    }
}
