// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::Read;

use anyhow::{anyhow, Result};
use oci_distribution::manifest::OciDescriptor;

use crate::blockcipher::{
    Finalizer, LayerBlockCipherHandler, LayerBlockCipherOptions, PrivateLayerBlockCipherOptions,
    PublicLayerBlockCipherOptions, AES256CTR,
};
use crate::config::{DecryptConfig, EncryptConfig};
#[cfg(feature = "keywrap-jwe")]
use crate::keywrap::jwe::JweKeyWrapper;
#[cfg(feature = "keywrap-keyprovider")]
use crate::keywrap::keyprovider;
use crate::keywrap::KeyWrapper;

lazy_static! {
    static ref KEY_WRAPPERS: HashMap<String, Box<dyn KeyWrapper>> = {
        #[allow(unused_mut)]
        let mut m = HashMap::new();

        #[cfg(feature = "keywrap-jwe")] {
            m.insert(
                "jwe".to_string(),
                Box::new(JweKeyWrapper {}) as Box<dyn KeyWrapper>,
            );
        }

        #[cfg(feature = "keywrap-keyprovider")] {
            // TODO: The error over here needs to be logged to be in consistent with golang version.
            let ocicrypt_config = crate::config::OcicryptConfig::from_env(crate::config::OCICRYPT_ENVVARNAME)
                .expect("Unable to read ocicrypt config file");
            let key_providers = ocicrypt_config.key_providers;
            for (provider_name, attrs) in key_providers.iter() {
                m.insert(
                    "provider.".to_owned() + provider_name,
                    Box::new(keyprovider::KeyProviderKeyWrapper::new(
                        provider_name.to_string(),
                        attrs.clone(),
                        None,
                    )) as Box<dyn KeyWrapper>,
                );
            }
        }

        m
    };
    static ref KEY_WRAPPERS_ANNOTATIONS: HashMap<String, String> = {
        let mut m = HashMap::new();
        for (scheme, key_wrapper) in KEY_WRAPPERS.iter() {
            m.insert(key_wrapper.annotation_id().to_string(), scheme.clone());
        }
        m
    };
}

// EncryptLayerFinalizer can get the annotations to set for the encrypted layer
#[derive(Debug, Default, Clone)]
pub struct EncLayerFinalizer {
    lbco: LayerBlockCipherOptions,
}

impl EncLayerFinalizer {
    pub fn finalized_annotations(
        &mut self,
        ec: &EncryptConfig,
        desc: &OciDescriptor,
        finalizer: Option<&mut impl Finalizer>,
    ) -> Result<HashMap<String, String>> {
        let mut priv_opts = vec![];
        let mut pub_opts = vec![];

        if finalizer.is_some() {
            finalizer.unwrap().finalized_lbco(&mut self.lbco)?;

            priv_opts = serde_json::to_vec(&self.lbco.private)?;
            pub_opts = serde_json::to_vec(&self.lbco.public)?;
        }

        let mut new_annotations = HashMap::new();

        let mut keys_wrapped = false;
        for (annotations_id, scheme) in KEY_WRAPPERS_ANNOTATIONS.iter() {
            let key_wrapper = get_key_wrapper(scheme)?;

            let mut b64_annotations = String::new();
            if let Some(annotations) = desc.annotations.as_ref() {
                if let Some(key_annotations) = annotations.get(annotations_id) {
                    b64_annotations = key_annotations.clone();
                }
            }

            b64_annotations = pre_wrap_key(key_wrapper, ec, b64_annotations, &priv_opts)?;
            if !b64_annotations.is_empty() {
                keys_wrapped = true;
                new_annotations.insert(annotations_id.to_string(), b64_annotations);
            }
        }

        if !keys_wrapped {
            return Err(anyhow!("no wrapped keys produced by encryption"));
        }

        if new_annotations.is_empty() {
            return Err(anyhow!("no encryptor found to handle encryption"));
        }

        new_annotations.insert(
            "org.opencontainers.image.enc.pubopts".to_string(),
            base64::encode(pub_opts),
        );

        Ok(new_annotations)
    }
}

/// get_key_wrapper looks up the encryptor interface given an encryption scheme (gpg, jwe)
#[allow(clippy::borrowed_box)]
pub fn get_key_wrapper(scheme: &str) -> Result<&Box<dyn KeyWrapper>> {
    KEY_WRAPPERS
        .get(scheme)
        .ok_or_else(|| anyhow!("key wrapper not supported!"))
}

/// get_wrapped_keys_map returns a option contains map of wrapped_keys
/// as values and the encryption scheme(s) as the key(s)
pub fn get_wrapped_keys_map(desc: OciDescriptor) -> HashMap<String, String> {
    let mut wrapped_keys_map = HashMap::new();
    for (annotations_id, scheme) in KEY_WRAPPERS_ANNOTATIONS.iter() {
        if let Some(annotations) = desc.annotations.as_ref() {
            if let Some(anno_id) = annotations.get(annotations_id) {
                wrapped_keys_map.insert(scheme.clone(), anno_id.clone());
            }
        }
    }

    wrapped_keys_map
}

// pre_wrap_keys calls wrap_keys and handles the base64 encoding and
// concatenation of the annotation data.
fn pre_wrap_key(
    keywrapper: &dyn KeyWrapper,
    ec: &EncryptConfig,
    mut b64_annotations: String,
    opts_data: &[u8],
) -> Result<String> {
    let new_annotation = keywrapper.wrap_keys(ec, opts_data)?;
    if new_annotation.is_empty() {
        return Err(anyhow!("new annotations is empty!"));
    }

    let b64_new_annotation = base64::encode(new_annotation);
    if b64_annotations.is_empty() {
        return Ok(b64_new_annotation);
    }

    b64_annotations.push(',');
    b64_annotations.push_str(&b64_new_annotation);
    Ok(b64_annotations)
}

// pre_unwrap_key decodes the comma separated base64 strings and calls the unwrap_key function
// of the given keywrapper with it and returns the result in case the unwrap_key functions
// does not return an error. If all attempts fail, an error is returned.
fn pre_unwrap_key(
    keywrapper: &dyn KeyWrapper,
    dc: &DecryptConfig,
    b64_annotations: &str,
) -> Result<Vec<u8>> {
    if b64_annotations.is_empty() {
        return Err(anyhow!("annotations is empty!"));
    }

    let mut errs = String::new();
    for b64_annotation in b64_annotations.split(',') {
        let annotation = base64::decode(b64_annotation)?;

        match keywrapper.unwrap_keys(dc, &annotation) {
            Err(e) => {
                errs.push_str(&e.to_string());
                continue;
            }
            Ok(opts_data) => {
                return Ok(opts_data);
            }
        };
    }

    Err(anyhow!(
        "no suitable key found for decrypting layer key:\n {}",
        errs
    ))
}

fn get_layer_pub_opts(desc: &OciDescriptor) -> Result<Vec<u8>> {
    if let Some(annotations) = desc.annotations.as_ref() {
        if let Some(pub_opts) = annotations.get("org.opencontainers.image.enc.pubopts") {
            return Ok(base64::decode(pub_opts)?);
        }
    }

    Ok(
        serde_json::to_string(&PublicLayerBlockCipherOptions::default())?
            .as_bytes()
            .to_vec(),
    )
}

fn decrypt_layer_key_opts_data(dc: &DecryptConfig, desc: &OciDescriptor) -> Result<Vec<u8>> {
    let mut priv_key_given = false;

    for (annotations_id, scheme) in KEY_WRAPPERS_ANNOTATIONS.iter() {
        if let Some(annotations) = desc.annotations.as_ref() {
            if let Some(b64_annotation) = annotations.get(annotations_id) {
                let keywrapper = get_key_wrapper(scheme)?;
                if !keywrapper.probe(&dc.param) {
                    continue;
                }

                if keywrapper.private_keys(&dc.param).is_some() {
                    priv_key_given = true;
                }

                if let Ok(opts_data) = pre_unwrap_key(&*keywrapper, dc, b64_annotation) {
                    if !opts_data.is_empty() {
                        return Ok(opts_data);
                    }
                }
                // try next keywrapper
            }
        }
    }

    if !priv_key_given {
        return Err(anyhow!("missing private key needed for decryption"));
    }

    Err(anyhow!(
        "no suitable key unwrapper found or none of the private keys could be used for decryption"
    ))
}

/// encrypt_layer encrypts the layer by running one encryptor after the other
pub fn encrypt_layer<'a, R: 'a + Read>(
    ec: &EncryptConfig,
    layer_reader: R,
    desc: &OciDescriptor,
) -> Result<(Option<impl Read + Finalizer + 'a>, EncLayerFinalizer)> {
    let mut encrypted = false;
    for (annotations_id, _scheme) in KEY_WRAPPERS_ANNOTATIONS.iter() {
        if let Some(annotations) = desc.annotations.as_ref() {
            if annotations.contains_key(annotations_id) {
                if let Some(decrypt_config) = ec.decrypt_config.as_ref() {
                    decrypt_layer_key_opts_data(decrypt_config, desc)?;
                    get_layer_pub_opts(desc)?;

                    // already encrypted!
                    encrypted = true;
                } else {
                    return Err(anyhow!("EncryptConfig must not be None"));
                }
            }
        }
    }

    if !encrypted {
        let mut lbch = LayerBlockCipherHandler::new()?;
        let mut lbco = LayerBlockCipherOptions::default();

        lbch.encrypt(layer_reader, AES256CTR, &mut lbco)?;
        lbco.private.digest = desc.digest.clone();
        let enc_layer_finalizer = EncLayerFinalizer { lbco };

        Ok((lbch.aes_ctr_block_cipher, enc_layer_finalizer))
    } else {
        Ok((None, EncLayerFinalizer::default()))
    }
}

// decrypt_layer decrypts a layer trying one keywrapper after the other to see whether it
// can apply the provided private key
// If unwrap_only is set we will only try to decrypt the layer encryption key and return
pub fn decrypt_layer<R: Read>(
    dc: &DecryptConfig,
    layer_reader: R,
    desc: &OciDescriptor,
    unwrap_only: bool,
) -> Result<(Option<impl Read>, String)> {
    let priv_opts_data = decrypt_layer_key_opts_data(dc, desc)?;
    let pub_opts_data = get_layer_pub_opts(desc)?;

    if unwrap_only {
        return Ok((None, "".to_string()));
    }

    let priv_opts: PrivateLayerBlockCipherOptions = serde_json::from_slice(&priv_opts_data)?;
    let mut lbch = LayerBlockCipherHandler::new()?;

    let pub_opts: PublicLayerBlockCipherOptions = serde_json::from_slice(&pub_opts_data)?;

    let mut opts = LayerBlockCipherOptions {
        public: pub_opts,
        private: priv_opts,
    };

    lbch.decrypt(layer_reader, &mut opts)?;

    Ok((lbch.aes_ctr_block_cipher, opts.private.digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_encrypt_decrypt_layer() {
        let path = load_data_path();
        let test_conf_path = format!("{}/{}", path, "ocicrypt_config.json");
        env::set_var("OCICRYPT_KEYPROVIDER_CONFIG", &test_conf_path);

        let pub_key_file = format!("{}/{}", path, "public_key.pem");
        let pub_key = fs::read(&pub_key_file).unwrap();

        let priv_key_file = format!("{}/{}", path, "private_key.pem");
        let priv_key = fs::read(&priv_key_file).unwrap();

        let mut ec = EncryptConfig::default();
        assert!(ec.encrypt_with_jwe(vec![pub_key.clone()]).is_ok());
        assert!(ec.encrypt_with_jwe(vec![pub_key]).is_ok());

        let mut dc = DecryptConfig::default();
        assert!(dc
            .decrypt_with_priv_keys(vec![priv_key.to_vec()], vec![vec![]])
            .is_ok());

        let layer_data: Vec<u8> = b"This is some text!".to_vec();
        let mut desc = OciDescriptor::default();
        let digest = format!("sha256:{:x}", Sha256::digest(&layer_data));
        desc.digest = digest.clone();

        let (layer_encryptor, mut elf) = encrypt_layer(&ec, layer_data.as_slice(), &desc).unwrap();

        let mut encrypted_data: Vec<u8> = Vec::new();
        let mut encryptor = layer_encryptor.unwrap();
        assert!(encryptor.read_to_end(&mut encrypted_data).is_ok());
        assert!(encryptor.finalized_lbco(&mut elf.lbco).is_ok());

        if let Ok(new_annotations) = elf.finalized_annotations(&ec, &desc, Some(&mut encryptor)) {
            let new_desc = OciDescriptor {
                annotations: Some(new_annotations),
                ..Default::default()
            };
            let (layer_decryptor, dec_digest) =
                decrypt_layer(&dc, encrypted_data.as_slice(), &new_desc, false).unwrap();
            let mut plaintxt_data: Vec<u8> = Vec::new();
            let mut decryptor = layer_decryptor.unwrap();

            assert!(decryptor.read_to_end(&mut plaintxt_data).is_ok());
            assert_eq!(layer_data, plaintxt_data);
            assert_eq!(digest, dec_digest);
        }
    }

    fn load_data_path() -> String {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("data");

        path.to_str().unwrap().to_string()
    }
}
