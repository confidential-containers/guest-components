// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Credentials to access aliyun KMS

use anyhow::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use log::debug;
use openssl::{
    pkey::{PKey, Private},
    sign::Signer,
};
use p12::{CertBag, ContentInfo, MacData, SafeBagKind, PFX};
use serde::Deserialize;
use yasna::ASN1Result;

#[derive(Clone, Debug)]
pub(crate) struct Credential {
    pub(crate) client_key_id: String,
    private_key: PKey<Private>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ClientKey {
    key_id: String,
    private_key_data: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Password {
    client_key_password: String,
}

impl Credential {
    pub(crate) fn new(client_key: &str, pswd: &str) -> Result<Self> {
        let ck: ClientKey = serde_json::from_str(client_key)?;

        let password: Password = serde_json::from_str(pswd)?;

        let private_key =
            Self::parse_private_key(ck.private_key_data, password.client_key_password)?;

        let private_key = PKey::private_key_from_der(&private_key)?;
        let credential = Credential {
            client_key_id: ck.key_id.clone(),
            private_key,
        };

        Ok(credential)
    }

    pub(crate) fn generate_bear_auth(&self, str_to_sign: &str) -> Result<String> {
        let mut signer = Signer::new(openssl::hash::MessageDigest::sha256(), &self.private_key)?;
        signer.update(str_to_sign.as_bytes())?;
        let signature = signer.sign_to_vec()?;

        Ok(format!("Bearer {}", STANDARD.encode(signature)))
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
