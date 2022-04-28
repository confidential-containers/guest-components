// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

use std::io::Read;

use anyhow::{anyhow, Result};
use ctr::cipher::generic_array::GenericArray;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use rand::{thread_rng, Rng};
use sha2::Sha256;

use crate::blockcipher::{EncryptionFinalizer, LayerBlockCipher, LayerBlockCipherOptions};

const AES256_KEY_SIZE: usize = 32;
const AES256_NONCE_SIZE: usize = 16;
type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

struct AESCTRBlockCipherState<R> {
    done: bool,
    cipher: Aes256Ctr,
    exp_hmac: Vec<u8>,
    hmac: HmacSha256,
    reader: R,
}

/// Implementation of the AES CTR stream cipher.
pub struct AESCTRBlockCipher<R> {
    key_len: usize,
    encrypt: bool,
    state: Option<AESCTRBlockCipherState<R>>,
}

impl<R> AESCTRBlockCipher<R> {
    /// Create a new instance of `AESCTRBlockCipher`.
    pub fn new(bits: usize) -> Result<AESCTRBlockCipher<R>> {
        if bits != AES256_KEY_SIZE * 8 {
            return Err(anyhow!("AES CTR bit count not supported"));
        }

        Ok(AESCTRBlockCipher {
            key_len: AES256_KEY_SIZE,
            encrypt: false,
            state: None,
        })
    }

    // init initializes an instance
    fn init(&mut self, encrypt: bool, reader: R, opts: &mut LayerBlockCipherOptions) -> Result<()> {
        let symmetric_key = &opts.private.symmetric_key;
        if symmetric_key.len() != AES256_KEY_SIZE {
            return Err(anyhow!(
                "invalid key length of {} bytes; need {} bytes",
                symmetric_key.len(),
                AES256_KEY_SIZE
            ));
        }
        if !encrypt && opts.public.hmac.is_empty() {
            return Err(anyhow!("HMAC is not provided for decryption process"));
        }

        let mut nonce = vec![0u8; AES256_NONCE_SIZE];
        match opts.get_opt("nonce") {
            Some(v) => {
                if v.len() != AES256_NONCE_SIZE {
                    return Err(anyhow!(
                        "invalid nonce length of {} bytes; need {} bytes",
                        nonce.len(),
                        AES256_NONCE_SIZE
                    ));
                }
                nonce = v;
            }
            None => thread_rng().try_fill(&mut nonce[..])?,
        }

        let cipher = Aes256Ctr::new(
            GenericArray::from_slice(symmetric_key.as_slice()),
            GenericArray::from_slice(nonce.as_slice()),
        );
        let hmac = HmacSha256::new_from_slice(symmetric_key.as_slice())
            .map_err(|_| anyhow!("Failed to create HMAC"))?;

        self.encrypt = encrypt;
        self.state = Some(AESCTRBlockCipherState {
            cipher,
            done: false,
            hmac,
            exp_hmac: opts.public.hmac.clone(),
            reader,
        });

        opts.private
            .cipher_options
            .entry("nonce".to_string())
            .or_insert(nonce);

        Ok(())
    }
}

impl<R> LayerBlockCipher<R> for AESCTRBlockCipher<R> {
    fn generate_key(&self) -> Result<Vec<u8>> {
        let mut key = vec![0; self.key_len];
        thread_rng().try_fill(&mut key[..])?;
        Ok(key)
    }

    fn encrypt(&mut self, input: R, opts: &mut LayerBlockCipherOptions) -> Result<()> {
        self.init(true, input, opts)
    }

    fn decrypt(&mut self, input: R, opts: &mut LayerBlockCipherOptions) -> Result<()> {
        self.init(false, input, opts)
    }
}

impl<R> EncryptionFinalizer for AESCTRBlockCipher<R> {
    fn finalized_lbco(&self, opts: &mut LayerBlockCipherOptions) -> Result<()> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| anyhow!("The AESCTRBlockCipher object hasn't been initialized yet"))?;
        if !state.done {
            Err(anyhow!("Read()ing not complete, unable to finalize"))
        } else {
            opts.public.hmac = state.exp_hmac.to_vec();
            Ok(())
        }
    }
}

impl<R: Read> Read for AESCTRBlockCipher<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::Unsupported))?;
        if state.done {
            return Ok(0);
        }

        let read_len = state.reader.read(buf)?;
        if read_len == 0 {
            state.done = true;
        }

        if !self.encrypt {
            if read_len > 0 {
                state.hmac.update(&buf[0..read_len]);
            }
            // If we done encrypting, let the HMAC comparison provide a verdict
            if state.done {
                state
                    .hmac
                    .clone()
                    .verify_slice(&state.exp_hmac)
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!(
                                "failed decrypt byte stream, exp hmac: {:?} , actual hmac: {:?}",
                                &state.exp_hmac,
                                state.hmac.clone().finalize().into_bytes()
                            ),
                        )
                    })?;
            }
            if read_len > 0 {
                state.cipher.apply_keystream(&mut buf[0..read_len]);
            }
        } else {
            if read_len > 0 {
                state.cipher.apply_keystream(&mut buf[0..read_len]);
                state.hmac.update(&buf[0..read_len]);
            }
            if state.done {
                state.exp_hmac = state.hmac.clone().finalize().into_bytes().to_vec();
            }
        }

        Ok(read_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;

    #[test]
    fn test_aes_ctr_block_cipher() {
        let layer_data: Vec<u8> = b"this is some data".to_vec();

        let mut lbco = LayerBlockCipherOptions::default();
        let mut aes_ctr_block_cipher = AESCTRBlockCipher::new(256).unwrap();

        // Error due to LayerBlockCipherOptions without symmetric key
        assert!(aes_ctr_block_cipher
            .encrypt(layer_data.as_slice(), &mut lbco)
            .is_err());

        let key = aes_ctr_block_cipher.generate_key().unwrap();
        lbco.private.symmetric_key = key;

        assert!(aes_ctr_block_cipher
            .encrypt(layer_data.as_slice(), &mut lbco)
            .is_ok());

        let mut encrypted_data: Vec<u8> = Vec::new();
        assert!(aes_ctr_block_cipher
            .read_to_end(&mut encrypted_data)
            .is_ok());

        assert!(aes_ctr_block_cipher.state.as_ref().unwrap().done);
        let finalizer = &mut aes_ctr_block_cipher;

        assert!(finalizer.finalized_lbco(&mut lbco).is_ok());

        let exp_hmac = aes_ctr_block_cipher
            .state
            .as_ref()
            .unwrap()
            .exp_hmac
            .to_vec();

        // Expected HMAC is empty
        lbco.public.hmac = vec![];
        assert!(aes_ctr_block_cipher
            .decrypt(encrypted_data.as_slice(), &mut lbco)
            .is_err());

        // Expected HMAC is wrong
        lbco.public.hmac = b"wrong hmac".to_vec();
        assert!(aes_ctr_block_cipher
            .decrypt(encrypted_data.as_slice(), &mut lbco)
            .is_ok());

        let mut plaintxt_data: Vec<u8> = Vec::new();
        assert!(aes_ctr_block_cipher
            .read_to_end(&mut plaintxt_data)
            .is_err());

        // Expected HMAC is right
        lbco.public.hmac = exp_hmac;
        assert!(aes_ctr_block_cipher
            .decrypt(encrypted_data.as_slice(), &mut lbco)
            .is_ok());

        let mut plaintxt_data: Vec<u8> = Vec::new();
        assert!(aes_ctr_block_cipher.read_to_end(&mut plaintxt_data).is_ok());
        assert!(aes_ctr_block_cipher.state.as_ref().unwrap().done);
        assert_eq!(layer_data, plaintxt_data);
    }

    #[test]
    // Verify different rust crypto crate have the same results
    fn test_crypto_crate() {
        let layer_data: Vec<u8> = b"this is some data".to_vec();

        let mut symmetric_key = vec![0; 32];
        thread_rng().try_fill(&mut symmetric_key[..]).unwrap();

        let mut nonce = vec![0; 16];
        thread_rng().try_fill(&mut nonce[..]).unwrap();

        let mut crypto_encrypt = Aes256Ctr::new(
            GenericArray::from_slice(symmetric_key.as_slice()),
            GenericArray::from_slice(nonce.as_slice()),
        );

        let openssl_cipher = openssl::symm::Cipher::aes_256_ctr();
        let openssl_ciphertext =
            openssl::symm::encrypt(openssl_cipher, &symmetric_key, Some(&nonce), &layer_data)
                .unwrap();

        let mut buffer = layer_data.clone();
        crypto_encrypt.apply_keystream(&mut buffer);

        assert_eq!(buffer, openssl_ciphertext);

        let openssl_plaintext = openssl::symm::decrypt(
            openssl_cipher,
            &symmetric_key,
            Some(&nonce),
            &openssl_ciphertext,
        )
        .unwrap();

        let mut crypto_decrypt = Aes256Ctr::new(
            GenericArray::from_slice(symmetric_key.as_slice()),
            GenericArray::from_slice(nonce.as_slice()),
        );

        crypto_decrypt.apply_keystream(&mut buffer);

        assert_eq!(buffer, openssl_plaintext);

        let mut hmac_sha256 =
            HmacSha256::new_from_slice(symmetric_key.as_slice()).expect("hmac use symmetric key");
        hmac_sha256.update(&layer_data);
        let crypto_hmac = hmac_sha256.finalize().into_bytes().to_vec();

        let openssl_pkey = PKey::hmac(&symmetric_key).unwrap();
        let mut openssl_signer = Signer::new(MessageDigest::sha256(), &openssl_pkey).unwrap();
        openssl_signer.update(&layer_data).unwrap();
        let openssl_hmac = openssl_signer.sign_to_vec().unwrap();

        assert_eq!(crypto_hmac, openssl_hmac);
    }
}
