// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::io::{Cursor, Read};

use anyhow::{anyhow, Result};
use oci_distribution::manifest::{self, OciDescriptor};
use ocicrypt_rs::config::CryptoConfig;
use ocicrypt_rs::encryption::decrypt_layer;
use ocicrypt_rs::helpers::create_decrypt_config;
use ocicrypt_rs::spec::{
    MEDIA_TYPE_LAYER_ENC, MEDIA_TYPE_LAYER_GZIP_ENC, MEDIA_TYPE_LAYER_NON_DISTRIBUTABLE_ENC,
    MEDIA_TYPE_LAYER_NON_DISTRIBUTABLE_GZIP_ENC,
};

#[derive(Default, Clone)]
pub struct Decryptor {
    /// The layer original media type before encryption.
    pub media_type: String,

    /// Whether layer is encrypted.
    encrypted: bool,
}

impl Decryptor {
    /// Construct Decryptor from media_type.
    pub fn from_media_type(media_type: &str) -> Self {
        let (media_type, encrypted) = match media_type {
            MEDIA_TYPE_LAYER_ENC | MEDIA_TYPE_LAYER_NON_DISTRIBUTABLE_ENC => {
                (manifest::IMAGE_LAYER_MEDIA_TYPE.to_string(), true)
            }
            MEDIA_TYPE_LAYER_GZIP_ENC | MEDIA_TYPE_LAYER_NON_DISTRIBUTABLE_GZIP_ENC => {
                (manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE.to_string(), true)
            }
            _ => ("".to_string(), false),
        };

        Decryptor {
            media_type,
            encrypted,
        }
    }

    /// Check whether media_type is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// get_plaintext_layer descrypts encrypted_layer data and return the
    /// plaintext_layer data. descriptor and decrypt_config are required for
    /// layer data decryption process.
    ///
    /// * `decrypt_config` - decryption key info in following format:\
    ///           - \<filename> \
    ///           - \<filename>:file=\<passwordfile> \
    ///           - \<filename>:pass=\<password> \
    ///           - \<filename>:fd=\<filedescriptor> \
    ///           - \<filename>:\<password> \
    ///           - provider:<cmd/gprc>
    pub fn get_plaintext_layer(
        &self,
        descriptor: &OciDescriptor,
        encrypted_layer: Vec<u8>,
        decrypt_config: &str,
    ) -> Result<Box<dyn Read + 'static>> {
        if !self.is_encrypted() {
            Err(anyhow!("unencrypted media type: {}", self.media_type))
        } else if decrypt_config.is_empty() {
            Err(anyhow!("decrypt_config is empty"))
        } else {
            let cc = create_decrypt_config(vec![decrypt_config.to_string()], vec![])?;
            decrypt_layer_data(encrypted_layer, descriptor, &cc)
        }
    }
}

fn decrypt_layer_data(
    encrypted_layer: Vec<u8>,
    descriptor: &OciDescriptor,
    crypto_config: &CryptoConfig,
) -> Result<Box<dyn Read + 'static>> {
    if let Some(decrypt_config) = crypto_config.decrypt_config.as_ref() {
        let (layer_decryptor, _dec_digest) = decrypt_layer(
            decrypt_config,
            Cursor::new(encrypted_layer),
            descriptor,
            false,
        )?;
        let decryptor = layer_decryptor.ok_or_else(|| anyhow!("missing layer decryptor"))?;
        Ok(Box::new(decryptor))
    } else {
        Err(anyhow!("no decrypt config available"))
    }
}
