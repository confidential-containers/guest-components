// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{image, kms, secret, storage};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("kbs client initialization failed")]
    KbsClient {
        #[source]
        source: kms::Error,
    },

    #[error("get resource failed")]
    GetResource {
        #[source]
        source: kms::Error,
    },

    #[error("decrypt image (unwrap key) failed")]
    ImageDecryption(#[from] image::Error),

    #[error("init Hub failed: {0}")]
    InitializationFailed(String),

    #[error("unseal secret failed")]
    UnsealSecret(#[from] secret::SecretError),

    #[error("secure mount failed")]
    SecureMount(#[from] storage::Error),

    #[error("image pull failed")]
    ImagePull {
        #[source]
        source: anyhow::Error,
    },
}
