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

use std::io::Read;

#[derive(Default, Clone, Debug)]
pub struct Decryptor {
    /// The layer original media type before encryption.
    pub media_type: String,

    /// Whether layer is encrypted.
    encrypted: bool,
}

impl Decryptor {
    const ERR_EMPTY_CFG: &str = "decrypt_config is empty";
    const ERR_UNENCRYPTED_MEDIA_TYPE: &str = "unencrypted media type";

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
    pub async fn get_plaintext_layer(
        &self,
        descriptor: &OciDescriptor,
        encrypted_layer: Vec<u8>,
        decrypt_config: &str,
    ) -> Result<Vec<u8>> {
        if !self.is_encrypted() {
            return Err(anyhow!(
                "{}: {}",
                Self::ERR_UNENCRYPTED_MEDIA_TYPE,
                self.media_type
            ));
        }

        if decrypt_config.is_empty() {
            return Err(anyhow!(Self::ERR_EMPTY_CFG));
        }

        let cc = create_decrypt_config(vec![decrypt_config.to_string()], vec![])?;
        let descript = descriptor.clone();

        // ocicrypt-rs keyprovider module will create a new runtime to talk with
        // attestation agent, to avoid startup a runtime within a runtime, we
        // spawn a new thread here.
        let handler = tokio::task::spawn_blocking(move || {
            decrypt_layer_data(&encrypted_layer, &descript, &cc)
        });

        if let Ok(decrypted_data) = handler.await? {
            Ok(decrypted_data)
        } else {
            Err(anyhow!("decrypt failed!"))
        }
    }
}

fn decrypt_layer_data(
    encrypted_layer: &[u8],
    descriptor: &OciDescriptor,
    crypto_config: &CryptoConfig,
) -> Result<Vec<u8>> {
    if let Some(decrypt_config) = &crypto_config.decrypt_config {
        let (layer_decryptor, _dec_digest) =
            decrypt_layer(decrypt_config, encrypted_layer, descriptor, false)?;
        let mut plaintext_data: Vec<u8> = Vec::new();
        let mut decryptor = layer_decryptor.ok_or_else(|| anyhow!("missing layer decryptor"))?;

        decryptor.read_to_end(&mut plaintext_data)?;

        Ok(plaintext_data)
    } else {
        Err(anyhow!("no decrypt config available"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile;
    use test_utils::assert_result;

    const ERR_OCICRYPT_RS_DECRYPT_FAIL: &str = "decrypt failed!";

    #[tokio::test]
    async fn test_from_media_type() {
        #[derive(Debug)]
        struct TestData<'a> {
            media_type: &'a str,
            result: Decryptor,
        }

        let tests = &[
            TestData {
                media_type: "",
                result: Decryptor {
                    media_type: "".into(),
                    encrypted: false,
                },
            },
            TestData {
                media_type: "invalid",
                result: Decryptor {
                    media_type: "".into(),
                    encrypted: false,
                },
            },
            TestData {
                media_type: "foo bar",
                result: Decryptor {
                    media_type: "".into(),
                    encrypted: false,
                },
            },
            TestData {
                media_type: MEDIA_TYPE_LAYER_ENC,
                result: Decryptor {
                    media_type: manifest::IMAGE_LAYER_MEDIA_TYPE.to_string().to_string(),
                    encrypted: true,
                },
            },
            TestData {
                media_type: MEDIA_TYPE_LAYER_NON_DISTRIBUTABLE_ENC,
                result: Decryptor {
                    media_type: manifest::IMAGE_LAYER_MEDIA_TYPE.to_string().to_string(),
                    encrypted: true,
                },
            },
            TestData {
                media_type: MEDIA_TYPE_LAYER_GZIP_ENC,
                result: Decryptor {
                    media_type: manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE.to_string(),
                    encrypted: true,
                },
            },
            TestData {
                media_type: MEDIA_TYPE_LAYER_NON_DISTRIBUTABLE_GZIP_ENC,
                result: Decryptor {
                    media_type: manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE.to_string(),
                    encrypted: true,
                },
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{}]: {:?}", i, d);

            let result = Decryptor::from_media_type(d.media_type);

            let msg = format!("{}: result: {:?}", msg, result);

            assert_eq!(result.media_type, d.result.media_type, "{:?}", msg);
            assert_eq!(result.encrypted, d.result.encrypted, "{:?}", msg);
        }
    }

    #[tokio::test]
    async fn test_get_plaintext_layer() {
        #[derive(Debug)]
        struct TestData<'a> {
            encrypted: bool,
            media_type: &'a str,
            descriptor: OciDescriptor,
            encrypted_layer: Vec<u8>,
            decrypt_config: &'a str,
            result: Result<Vec<u8>>,
        }

        let tests = &[
            TestData {
                encrypted: false,
                media_type: "",
                descriptor: OciDescriptor::default(),
                encrypted_layer: Vec::<u8>::new(),
                decrypt_config: "",
                result: Err(anyhow!("{}: {}", Decryptor::ERR_UNENCRYPTED_MEDIA_TYPE, "")),
            },
            TestData {
                encrypted: false,
                media_type: "",
                descriptor: OciDescriptor::default(),
                encrypted_layer: Vec::<u8>::new(),
                decrypt_config: "foo",
                result: Err(anyhow!("{}: {}", Decryptor::ERR_UNENCRYPTED_MEDIA_TYPE, "")),
            },
            TestData {
                encrypted: true,
                media_type: "",
                descriptor: OciDescriptor::default(),
                encrypted_layer: Vec::<u8>::new(),
                decrypt_config: "foo",
                result: Err(anyhow!(ERR_OCICRYPT_RS_DECRYPT_FAIL)),
            },
            TestData {
                encrypted: true,
                media_type: MEDIA_TYPE_LAYER_ENC,
                descriptor: OciDescriptor::default(),
                encrypted_layer: Vec::<u8>::new(),
                decrypt_config: "foo",
                result: Err(anyhow!(ERR_OCICRYPT_RS_DECRYPT_FAIL)),
            },
        ];

        let tempdir = tempfile::tempdir().unwrap();

        let keyprovider_config_path = tempdir.path().join("keyconfig");
        let mut keyprovider_config = File::create(keyprovider_config_path.clone()).unwrap();

        let data = r#"
        {
            "key-providers": {
                "keyprovider1": {
                    "cmd": {
                        "path": "/bin/true",
                        "args": []
                    }
                }
            }
        }
        "#;

        keyprovider_config.write_all(data.as_bytes()).unwrap();

        std::env::set_var(
            ocicrypt_rs::config::OCICRYPT_ENVVARNAME,
            keyprovider_config_path,
        );

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{}]: {:?}", i, d);

            let decryptor = Decryptor {
                media_type: d.media_type.to_string(),
                encrypted: d.encrypted,
            };

            let plaintext_layer = decryptor.get_plaintext_layer(
                &d.descriptor,
                d.encrypted_layer.clone(),
                d.decrypt_config,
            );
            let result = plaintext_layer.await;

            let msg = format!("{}: result: {:?}", msg, result);

            assert_result!(d.result, result, msg);
        }
    }
}
