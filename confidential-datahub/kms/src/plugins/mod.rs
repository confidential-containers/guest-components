// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{Decrypter, Error, ProviderSettings, Result};

const IN_GUEST_DEFAULT_KEY_PATH: &str = "/run/confidential-containers/cdh/kms-credential";

#[cfg(feature = "aliyun")]
pub mod aliyun;

/// Create a new [`Decrypter`] by given provider name and [`ProviderSettings`]
pub async fn new_decryptor(
    provider: &str,
    _provider_settings: ProviderSettings,
) -> Result<Box<dyn Decrypter>> {
    match provider {
        #[cfg(feature = "aliyun")]
        "aliyun" => Ok(Box::new(
            aliyun::AliyunKmsClient::from_provider_settings(&_provider_settings).await?,
        ) as Box<dyn Decrypter>),
        p => Err(Error::UnsupportedProvider(p.to_string())),
    }
}
