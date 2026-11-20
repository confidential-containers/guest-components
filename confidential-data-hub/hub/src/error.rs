// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{image, secret, storage};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("kbc client initialization failed: {source}")]
    KbcClientInitialization {
        #[source]
        source: anyhow::Error,
    },

    #[error("Get Resource failed: {source}")]
    GetResource {
        #[source]
        source: anyhow::Error,
    },

    #[error("Decrypt Image (UnwrapKey) failed")]
    ImageDecryption(#[from] image::Error),

    #[error("init Hub failed: {0}")]
    InitializationFailed(String),

    #[error("Unseal Secret failed")]
    UnsealSecret(#[from] secret::SecretError),

    #[error("Secure Mount failed")]
    SecureMount(#[from] storage::Error),

    #[error("Image Pull error: {0}")]
    ImagePull(#[from] image_rs::image::PullImageError),

    #[error("Image Client error: {0}")]
    ImageClient(#[from] image_rs::builder::BuilderError),

    #[error("Attestation Agent client error: {source}")]
    AttestationAgentClientError {
        #[source]
        source: anyhow::Error,
    },
}
#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use image_rs::signature::SignatureError;
    use rstest::rstest;

    #[rstest]
    #[case(Error::KbcClientInitialization { source: anyhow!("details") }, "kbc client initialization failed: details")]
    #[case(Error::GetResource { source: anyhow!("details") }, "Get Resource failed: details")]
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
    #[case(Error::ImagePull(image_rs::image::PullImageError::SignatureValidationFailed(SignatureError::DeniedByPolicy { source: anyhow!("some details")})), "Image Pull error: Image policy rejected: Denied by policy: some details")]
    fn test_brief_message(#[case] error: Error, #[case] expected: &str) {
        let brief_message = error.to_string();
        assert_eq!(brief_message, expected);
    }
}
