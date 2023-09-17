// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::env;

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use image::{annotation_packet::v2::DEFAULT_VERSION, AnnotationPacket};
use jwt_simple::prelude::{Claims, Duration, Ed25519KeyPair, EdDSAKeyPairLike};
use kms::{Annotations, ProviderSettings};
use log::debug;
use rand::RngCore;
use reqwest::Url;
use resource_uri::ResourceUri;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::ImageEncrypter;

const KBS_URL_PATH_PREFIX: &str = "kbs/v0/resource";
pub const KBS_ADDR_ENV_KEY: &str = "KBS_ADDR";
pub const KBS_PRIVATE_KEY_PATH_ENV_KEY: &str = "KBS_PRIVATE_KEY_PATH";

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub kbs_addr: String,
    pub private_key_path: String,
}

pub struct Client {
    kbs_addr: Url,
    private_key: Ed25519KeyPair,
}

#[async_trait]
impl ImageEncrypter for Client {
    async fn encrypt_lek(
        &mut self,
        lek: &[u8],
        kek_id: Option<String>,
        kek: Option<Vec<u8>>,
    ) -> Result<AnnotationPacket> {
        let (kek, iv, kid) = Self::generate_key_parameters(kek_id, kek)?;
        let wrapped_data = crypto::encrypt(
            Zeroizing::new(kek.clone()),
            lek.to_vec(),
            iv.clone(),
            crypto::WrapType::Aes256Gcm,
        )?;
        let annotation_packet = AnnotationPacket {
            version: DEFAULT_VERSION.into(),
            kid: kid.whole_uri(),
            wrapped_data: STANDARD.encode(wrapped_data),
            provider: "kbs".into(),
            iv: Some(STANDARD.encode(iv)),
            wrap_type: Some(crypto::WrapType::Aes256Gcm.as_ref().to_string()),
            provider_settings: ProviderSettings::default(),
            annotations: Annotations::default(),
        };

        self.register_kek(kek, &kid.resource_path()).await?;
        Ok(annotation_packet)
    }
}

impl Client {
    pub async fn new() -> Result<Self> {
        let kbs_addr = env::var(KBS_ADDR_ENV_KEY)?;
        let kbs_addr = Url::try_from(&kbs_addr[..])?;
        let private_key_path = env::var(KBS_PRIVATE_KEY_PATH_ENV_KEY)?;

        let private_key = tokio::fs::read_to_string(private_key_path).await?;
        let private_key = Ed25519KeyPair::from_pem(&private_key)?;

        Ok(Self {
            kbs_addr,
            private_key,
        })
    }

    /// This function will generate (key, iv, keyid) for given `InputParams`
    fn generate_key_parameters(
        kek_id: Option<String>,
        kek: Option<Vec<u8>>,
    ) -> Result<(Vec<u8>, Vec<u8>, ResourceUri)> {
        let kek_id = match kek_id {
            Some(id) => {
                let id = Self::normalize_path(&id)?;
                ResourceUri::try_from(&id[..])
                    .map_err(|_| anyhow!("parse kek_id {id} to ResourceUri failed"))?
            }
            None => {
                debug!("no kid input, generate a random kid");
                let tag = uuid::Uuid::new_v4().to_string();
                ResourceUri {
                    kbs_addr: "".into(),
                    repository: "default".into(),
                    r#type: "image-kek".into(),
                    tag,
                }
            }
        };

        let kek = match kek {
            Some(k) => k.to_vec(),
            None => {
                debug!("no key input, generate a random key");

                let mut key = [0; 32];
                rand::rngs::OsRng.fill_bytes(&mut key);

                key.to_vec()
            }
        };

        let mut iv = [0; 12];
        rand::rngs::OsRng.fill_bytes(&mut iv);

        Ok((kek, iv.to_vec(), kek_id))
    }

    async fn register_kek(&self, key: Vec<u8>, key_path: &str) -> Result<()> {
        let kid = key_path.strip_prefix('/').unwrap_or(key_path);
        let claims = Claims::create(Duration::from_hours(2));
        let token = self.private_key.sign(claims)?;
        debug!("sign claims.");

        let client = reqwest::Client::new();
        let mut resource_url = self.kbs_addr.clone();

        let path = format!("{KBS_URL_PATH_PREFIX}/{kid}");

        resource_url.set_path(&path);

        debug!("register KEK into {}", resource_url);
        let _ = client
            .post(resource_url)
            .header("Content-Type", "application/octet-stream")
            .bearer_auth(token)
            .body(key)
            .send()
            .await?;

        Ok(())
    }

    /// Normalize the given keyid into [`ResourceUri`], s.t.
    /// converting `kbs://...` or `../..` to `kbs:///<repository>/<type>/<tag>)`.
    fn normalize_path(keyid: &str) -> Result<String> {
        debug!("normalize key id {keyid}");
        let path = keyid.strip_prefix("kbs://").unwrap_or(keyid);
        let values: Vec<&str> = path.split('/').collect();
        if values.len() == 4 {
            Ok(format!("kbs:///{}/{}/{}", values[1], values[2], values[3]))
        } else {
            bail!(
                "Resource path {keyid} must follow one of the following formats:
                    'kbs:///<repository>/<type>/<tag>'
                    'kbs://<kbs-addr>/<repository>/<type>/<tag>'
                    '<kbs-addr>/<repository>/<type>/<tag>'
                    '/<repository>/<type>/<tag>'
                "
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    #[rstest]
    #[case("kbs://a/b/c/d", "kbs:///b/c/d")]
    #[case("kbs:///b/c/d", "kbs:///b/c/d")]
    #[case("a/b/c/d", "kbs:///b/c/d")]
    #[case("/b/c/d", "kbs:///b/c/d")]
    fn test_normalize_keypath(#[case] input: &str, #[case] expected: &str) {
        let res = super::Client::normalize_path(input).expect("normalize failed");
        assert_eq!(res, expected);
    }
}
