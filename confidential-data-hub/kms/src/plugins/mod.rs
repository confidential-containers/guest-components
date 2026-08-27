// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::str::FromStr;

use strum::{AsRefStr, EnumString};

use crate::{Decrypter, Error, Getter, ProviderSettings, Result};

const _IN_GUEST_DEFAULT_KEY_PATH: &str = "/run/confidential-containers/cdh/kbs/kms-credential";

#[cfg(feature = "aliyun")]
pub mod aliyun;

#[cfg(feature = "aws")]
pub mod aws;

pub mod kbs;

#[derive(AsRefStr, EnumString)]
pub enum DecryptorProvider {
    #[cfg(feature = "aliyun")]
    #[strum(ascii_case_insensitive)]
    Aliyun,

    #[cfg(feature = "aws")]
    #[strum(ascii_case_insensitive)]
    Aws,
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

        #[cfg(feature = "aws")]
        DecryptorProvider::Aws => Ok(Box::new(
            aws::AwsKmsClient::from_provider_settings(&_provider_settings).await?,
        ) as Box<dyn Decrypter>),
    }
}

#[derive(AsRefStr, EnumString)]
pub enum VaultProvider {
    #[strum(ascii_case_insensitive)]
    Kbs,

    #[cfg(feature = "aliyun")]
    #[strum(ascii_case_insensitive)]
    Aliyun,

    #[cfg(feature = "aws")]
    #[strum(ascii_case_insensitive)]
    Aws,
}

/// Create a new [`Getter`] by given provider name and [`ProviderSettings`]
pub async fn new_getter(
    provider_name: &str,
    _provider_settings: ProviderSettings,
) -> Result<Box<dyn Getter>> {
    let provider = VaultProvider::from_str(provider_name)
        .map_err(|_| Error::UnsupportedProvider(provider_name.to_string()))?;
    match provider {
        VaultProvider::Kbs => Ok(Box::new(kbs::KbcClient::new().await?) as Box<dyn Getter>),

        #[cfg(feature = "aliyun")]
        VaultProvider::Aliyun => Ok(Box::new(
            aliyun::AliyunKmsClient::from_provider_settings(&_provider_settings).await?,
        ) as Box<dyn Getter>),

        #[cfg(feature = "aws")]
        VaultProvider::Aws => Ok(Box::new(
            aws::AwsKmsClient::from_provider_settings(&_provider_settings).await?,
        ) as Box<dyn Getter>),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ProviderSettings,
        plugins::{new_decryptor, new_getter},
    };

    #[tokio::test]
    async fn new_getter_unsupported_provider_returns_error() {
        let result = new_getter("no_such_provider", ProviderSettings::default()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn new_decryptor_unsupported_provider_returns_error() {
        let result = new_decryptor("no_such_provider", ProviderSettings::default()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn new_getter_empty_string_provider_returns_error() {
        let result = new_getter("", ProviderSettings::default()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn new_decryptor_empty_string_provider_returns_error() {
        let result = new_decryptor("", ProviderSettings::default()).await;
        assert!(result.is_err());
    }
}
