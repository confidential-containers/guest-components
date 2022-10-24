// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use ocicrypt_rs::config::CryptoConfig;
use ocicrypt_rs::encryption::decrypt_layer;
use ocicrypt_rs::helpers::create_decrypt_config;
use ocicrypt_rs::spec::{
    MEDIA_TYPE_LAYER_ENC, MEDIA_TYPE_LAYER_GZIP_ENC, MEDIA_TYPE_LAYER_NON_DISTRIBUTABLE_ENC,
    MEDIA_TYPE_LAYER_NON_DISTRIBUTABLE_GZIP_ENC,
};

use oci_distribution::manifest;
use oci_distribution::manifest::OciDescriptor;

use std::io;

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
    pub async fn get_plaintext_layer<
        R: io::Read + Send + 'static,
        W: io::Write + Send + 'static,
    >(
        &self,
        descriptor: &OciDescriptor,
        encrypted_layer: R,
        decrypt_config: &str,
        plaintext_layer: W,
    ) -> Result<()> {
        if !self.is_encrypted() {
            return Err(anyhow!("unencrypted media type: {}", self.media_type));
        }

        if decrypt_config.is_empty() {
            return Err(anyhow!("decrypt_config is empty"));
        }

        let cc = create_decrypt_config(vec![decrypt_config.to_string()], vec![])?;
        let descript = descriptor.clone();

        // ocicrypt-rs keyprovider module will create a new runtime to talk with
        // attestation agent, to avoid startup a runtime within a runtime, we
        // spawn a new thread here.
        let handler = tokio::task::spawn_blocking(move || {
            decrypt_layer_data(encrypted_layer, &descript, &cc, plaintext_layer)
        });

        if let Ok(()) = handler.await? {
            Ok(())
        } else {
            Err(anyhow!("decrypt failed!"))
        }
    }
}

fn decrypt_layer_data<R: io::Read + Send + 'static, W: io::Write + Send + 'static>(
    encrypted_layer: R,
    descriptor: &OciDescriptor,
    crypto_config: &CryptoConfig,
    mut plaintext_layer: W,
) -> Result<()> {
    if let Some(decrypt_config) = &crypto_config.decrypt_config {
        let (layer_decryptor, _dec_digest) =
            decrypt_layer(decrypt_config, encrypted_layer, descriptor, false)?;
        let mut decryptor = layer_decryptor.ok_or_else(|| anyhow!("missing layer decryptor"))?;

        std::io::copy(&mut decryptor, &mut plaintext_layer)?;

        Ok(())
    } else {
        Err(anyhow!("no decrypt config available"))
    }
}
