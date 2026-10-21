// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use openssl::{
    encrypt::Decrypter,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::{Padding, Rsa},
};
use zeroize::Zeroizing;

use crate::rsa::{PaddingMode, RSA_PUBKEY_LENGTH};

#[derive(Debug, Clone)]
pub struct RSAKeyPair {
    private_key: Rsa<Private>,
}

impl RSAKeyPair {
    pub fn new() -> Result<RSAKeyPair> {
        let private_key = Rsa::generate(RSA_PUBKEY_LENGTH as u32)?;
        Ok(Self { private_key })
    }

    pub fn decrypt(&self, mode: PaddingMode, cipher_text: Vec<u8>) -> Result<Vec<u8>> {
        match mode {
            PaddingMode::OAEP => self.decrypt_oaep_sha256(&cipher_text),
            #[allow(deprecated)]
            PaddingMode::PKCS1v15 => {
                let mut plaintext = [0; RSA_PUBKEY_LENGTH];
                let decrypted_size = self
                    .private_key
                    .private_decrypt(&cipher_text, &mut plaintext, Padding::PKCS1)
                    .map_err(|e| anyhow!("RSA key pkcs1v15 decrypt failed: {:?}", e))?;
                Ok(plaintext[..decrypted_size].to_vec())
            }
        }
    }

    fn decrypt_oaep_sha256(&self, cipher_text: &[u8]) -> Result<Vec<u8>> {
        let pkey = PKey::from_rsa(self.private_key.clone())?;
        let mut decrypter = Decrypter::new(&pkey)?;
        decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
        decrypter.set_rsa_oaep_md(MessageDigest::sha256())?;
        decrypter.set_rsa_mgf1_md(MessageDigest::sha256())?;

        let mut plaintext = vec![0; decrypter.decrypt_len(cipher_text)?];
        let decrypted_size = decrypter
            .decrypt(cipher_text, &mut plaintext)
            .map_err(|e| anyhow!("RSA key decrypt OAEP failed: {:?}", e))?;
        plaintext.truncate(decrypted_size);
        Ok(plaintext)
    }

    pub fn n(&self) -> Vec<u8> {
        self.private_key.n().to_vec()
    }

    pub fn e(&self) -> Vec<u8> {
        self.private_key.e().to_vec()
    }

    pub fn to_pkcs1_pem(&self) -> Result<Zeroizing<String>> {
        let res = self.private_key.private_key_to_pem()?;
        let pem = String::from_utf8(res)?;
        Ok(Zeroizing::new(pem))
    }

    pub fn from_pkcs1_pem(pem: &str) -> Result<Self> {
        let private_key = Rsa::<Private>::private_key_from_pem(pem.as_bytes())?;

        Ok(Self { private_key })
    }
}

#[cfg(test)]
mod tests {
    use openssl::encrypt::Encrypter;

    use super::*;

    fn encrypt_oaep(key: &RSAKeyPair, md: MessageDigest, plaintext: &[u8]) -> Result<Vec<u8>> {
        let pkey = PKey::from_rsa(key.private_key.clone())?;
        let mut encrypter = Encrypter::new(&pkey)?;
        encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
        encrypter.set_rsa_oaep_md(md)?;
        encrypter.set_rsa_mgf1_md(md)?;

        let mut cipher_text = vec![0; encrypter.encrypt_len(plaintext)?];
        let len = encrypter.encrypt(plaintext, &mut cipher_text)?;
        cipher_text.truncate(len);
        Ok(cipher_text)
    }

    #[test]
    fn oaep_sha256_roundtrip() {
        let key = RSAKeyPair::new().expect("generate rsa key");
        let plaintext = b"content-encryption-key-32-bytes!";
        let cipher_text =
            encrypt_oaep(&key, MessageDigest::sha256(), plaintext).expect("encrypt oaep sha256");

        let decrypted = key
            .decrypt(PaddingMode::OAEP, cipher_text)
            .expect("decrypt oaep sha256");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn oaep_sha1_ciphertext_is_rejected() {
        let key = RSAKeyPair::new().expect("generate rsa key");
        let cipher_text =
            encrypt_oaep(&key, MessageDigest::sha1(), b"cek").expect("encrypt oaep sha1");

        key.decrypt(PaddingMode::OAEP, cipher_text)
            .expect_err("sha1 oaep must not decrypt as RSA-OAEP-256");
    }
}
