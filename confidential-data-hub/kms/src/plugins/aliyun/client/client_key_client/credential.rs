// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Credentials to access aliyun KMS

use anyhow::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use log::debug;
use p12::{CertBag, ContentInfo, MacData, SafeBagKind, PFX};
use ring::{rand::SystemRandom, rsa::KeyPair, signature::RSA_PKCS1_SHA256};
use serde::Deserialize;
use yasna::ASN1Result;

#[derive(Clone, Debug)]
pub(crate) struct CredentialClientKey {
    pub client_key_id: String,
    private_key: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ClientKey {
    key_id: String,
    private_key_data: String,
}

// implement CredentialClientKey related function
impl CredentialClientKey {
    pub(crate) fn new(client_key: &str, pswd: &str) -> Result<Self> {
        let ck: ClientKey = serde_json::from_str(client_key)?;

        let private_key = Self::parse_private_key(ck.private_key_data, pswd.to_string())?;

        let credential = CredentialClientKey {
            client_key_id: ck.key_id.clone(),
            private_key,
        };

        Ok(credential)
    }

    pub(crate) fn sign(&self, str_to_sign: &str) -> Result<String> {
        let mut signature = Vec::new();
        let private_key = KeyPair::from_der(&self.private_key)
            .map_err(|_| anyhow!("read RSA private key failed"))?;
        private_key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                str_to_sign.as_bytes(),
                &mut signature,
            )
            .map_err(|_| anyhow!("signing failed"))?;

        Ok(STANDARD.encode(signature))
    }

    pub(crate) fn parse_private_key(private_key_data: String, password: String) -> Result<Vec<u8>> {
        let private_key_der = STANDARD.decode(private_key_data.as_bytes())?;
        let pfx = yasna::parse_der(&private_key_der, |r| -> ASN1Result<PFX> {
            r.read_sequence(|r| {
                let version = r.next().read_u8()?;
                let auth_safe = ContentInfo::parse(r.next())?;
                let mac_data = r.read_optional(MacData::parse).ok().flatten();
                std::result::Result::Ok(PFX {
                    version,
                    auth_safe,
                    mac_data,
                })
            })
        })?;

        let bags = pfx.bags(&password)?;
        for bag in &bags {
            match &bag.bag {
                SafeBagKind::Pkcs8ShroudedKeyBag(k) => {
                    let pass = Self::bmp_string(&password);
                    let private_key = k
                        .encryption_algorithm
                        .decrypt_pbe(&k.encrypted_data, &pass)
                        .ok_or(anyhow!("decrypt pbe failed"))?;
                    return Ok(private_key);
                }
                SafeBagKind::CertBag(e) => match e {
                    CertBag::X509(x) => {
                        debug!("parse aliyun pkcs12 credential X509: {}", hex::encode(x))
                    }
                    CertBag::SDSI(s) => debug!("parse aliyun pkcs12 credential SDSI: {:?}", s),
                },
                _ => continue,
            }
        }

        Err(anyhow!("no private key found!"))
    }

    fn bmp_string(s: &str) -> Vec<u8> {
        let utf16: Vec<u16> = s.encode_utf16().collect();

        let mut bytes = Vec::with_capacity(utf16.len() * 2 + 2);
        for c in utf16 {
            bytes.push((c / 256) as u8);
            bytes.push((c % 256) as u8);
        }
        bytes.push(0x00);
        bytes.push(0x00);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::CredentialClientKey;

    #[test]
    fn parse_test_password() {
        let password = "c4d1d2bba724194c9ca872ba8806c55d";
        let key = "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";
        CredentialClientKey::parse_private_key(key.to_owned(), password.to_owned()).unwrap();
    }
}
