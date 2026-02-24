// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Credentials to access aliyun KMS

use anyhow::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use p12::{CertBag, ContentInfo, MacData, SafeBagKind, PFX};
use ring::{rand::SystemRandom, rsa::KeyPair, signature::RSA_PKCS1_SHA256};
use serde::Deserialize;
use tracing::debug;
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

        let private_key =
            Self::parse_private_key(ck.private_key_data, pswd.trim_end().to_string())?;

        let credential = CredentialClientKey {
            client_key_id: ck.key_id.clone(),
            private_key,
        };

        Ok(credential)
    }

    pub(crate) fn sign(&self, str_to_sign: &str) -> Result<String> {
        let mut signature = Vec::new();
        let private_key = KeyPair::from_pkcs8(&self.private_key)
            .map_err(|_| anyhow!("read RSA private key failed"))?;
        signature.resize(private_key.public().modulus_len(), 0);
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
                    CertBag::SDSI(s) => debug!("parse aliyun pkcs12 credential SDSI: {s:?}"),
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
    fn parse_and_sign_password() {
        let password = "c383f5528f54394676ca89b8e47096e7";
        let key = "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";
        let der =
            CredentialClientKey::parse_private_key(key.to_owned(), password.to_owned()).unwrap();
        let key = CredentialClientKey {
            client_key_id: "test-id".into(),
            private_key: der,
        };

        key.sign("example content").unwrap();
    }
}
