// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use strum::{AsRefStr, EnumString};

use crate::{Decrypter, Error, Getter, ProviderSettings, PubkeyProvider, Result};

const _IN_GUEST_DEFAULT_KEY_PATH: &str = "/run/confidential-containers/cdh/kms-credential";

#[cfg(feature = "aliyun")]
pub mod aliyun;

pub mod kbs;

#[cfg(feature = "ehsm")]
pub mod ehsm;

#[derive(AsRefStr, EnumString)]
pub enum DecryptorProvider {
    #[cfg(feature = "aliyun")]
    #[strum(ascii_case_insensitive)]
    Aliyun,

    #[strum(ascii_case_insensitive)]
    #[cfg(feature = "ehsm")]
    Ehsm,
}

/// Create a new [`Decrypter`] by given provider name and [`ProviderSettings`]
pub async fn new_decryptor(
    provider_name: &str,
    _provider_settings: ProviderSettings,
) -> Result<Box<dyn Decrypter>> {
    let provider = DecryptorProvider::try_from(provider_name)
        .map_err(|_| Error::UnsupportedProvider(provider_name.to_string()))?;
    match provider {
        #[cfg(feature = "aliyun")]
        DecryptorProvider::Aliyun => Ok(Box::new(
            aliyun::AliyunKmsClient::from_provider_settings(&_provider_settings).await?,
        ) as Box<dyn Decrypter>),

        #[cfg(feature = "ehsm")]
        DecryptorProvider::Ehsm => Ok(Box::new(
            ehsm::EhsmKmsClient::from_provider_settings(&_provider_settings).await?,
        ) as Box<dyn Decrypter>),
    }
}

#[derive(AsRefStr, EnumString)]
pub enum VaultProvider {
    #[cfg(feature = "kbs")]
    #[strum(ascii_case_insensitive)]
    Kbs,
}

/// Create a new [`Getter`] by given provider name and [`ProviderSettings`]
pub async fn new_getter(
    provider_name: &str,
    _provider_settings: ProviderSettings,
) -> Result<Box<dyn Getter>> {
    let provider = VaultProvider::try_from(provider_name)
        .map_err(|_| Error::UnsupportedProvider(provider_name.to_string()))?;
    match provider {
        VaultProvider::Kbs => Ok(Box::new(kbs::KbcClient::new().await?) as Box<dyn Getter>),
    }
}

#[derive(AsRefStr, EnumString)]
pub enum PublicKeyProvider {
    #[cfg(feature = "kbs")]
    #[strum(ascii_case_insensitive)]
    Kbs,
    #[cfg(feature = "aliyun")]
    #[strum(ascii_case_insensitive)]
    Aliyun,
}

/// Create a new [`PubkeyProvider`] by given provider name
async fn new_public_key_provider(provider_name: &str) -> Result<Box<dyn PubkeyProvider>> {
    let provider = PublicKeyProvider::try_from(provider_name)
        .map_err(|_| Error::UnsupportedProvider(provider_name.to_string()))?;
    match provider {
        #[cfg(feature = "kbs")]
        PublicKeyProvider::Kbs => {
            Ok(Box::new(kbs::KbcClient::new().await?) as Box<dyn PubkeyProvider>)
        }
        #[cfg(feature = "aliyun")]
        PublicKeyProvider::Aliyun => Ok(Box::new(
            aliyun::AliyunKmsClient::from_provider_settings(&ProviderSettings::default()).await?,
        ) as Box<dyn PubkeyProvider>),
    }
}

/// Get the public key due to the given `key_id`.
/// For example `key_id`:
///
/// - KBS: `kbs:///default/key/1`
/// - Aliyun KMS: `aliyun://key-shh65012626mpi4oxxxxx`
pub async fn get_public_key(key_id: &str) -> Result<Vec<u8>> {
    let (provider, keyid) = key_id
        .split_once("://")
        .ok_or(Error::UnsupportedPublicKeyId(key_id.to_string()))?;
    let mut provider = new_public_key_provider(provider).await?;
    let pubkey = provider.get_public_key(keyid).await?;
    Ok(pubkey)
}
