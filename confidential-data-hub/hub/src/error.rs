// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{image, secret, storage};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("kbs client initialization failed")]
    KbsClient {
        #[source]
        source: kms::Error,
    },

    #[error("Get Resource failed")]
    GetResource {
        #[source]
        source: kms::Error,
    },

    #[error("Decrypt Image (UnwrapKey) failed")]
    ImageDecryption(#[from] image::Error),

    #[error("init Hub failed: {0}")]
    InitializationFailed(String),

    #[error("Unseal Secret failed")]
    UnsealSecret(#[from] secret::SecretError),

    #[error("Secure Mount failed")]
    SecureMount(#[from] storage::Error),

    #[error("Image Pull failed: {source}")]
    ImagePull {
        #[source]
        source: image_rs::PullImageError,
    },
}
#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use rstest::rstest;

    #[rstest]
    #[case(Error::KbsClient { source: kms::Error::KbsClientError("details".into()) }, "kbs client initialization failed")]
    #[case(Error::GetResource { source: kms::Error::KbsClientError("details".into()) }, "Get Resource failed")]
    #[case(
        Error::UnsealSecret(secret::SecretError::VersionError),
        "Unseal Secret failed"
    )]
    #[case(
        Error::SecureMount(storage::Error::StorageTypeNotRecognized(
            strum::ParseError::VariantNotFound
        )),
        "Secure Mount failed"
    )]
    #[case(Error::ImagePull {source: image_rs::PullImageError::SignatureValidationFailed{source: anyhow!("details")}}, "Image Pull failed: Image policy rejected")]
    fn test_brief_message(#[case] error: Error, #[case] expected: &str) {
        let brief_message = error.to_string();
        assert_eq!(brief_message, expected);
    }
}
