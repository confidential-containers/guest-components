// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

use crate::secret::{
    layout::{envelope::EnvelopeError, vault::VaultError},
    VERSION,
};

pub type Result<T> = std::result::Result<T, SecretError>;

#[derive(Error, Debug)]
pub enum SecretError {
    #[error("version not supported, only {} supported", VERSION)]
    VersionError,

    #[error(transparent)]
    UnsealEnvelopeFailed(#[from] EnvelopeError),

    #[error(transparent)]
    UnsealVaultFailed(#[from] VaultError),

    #[error("parse SealedSecret failed: {0}")]
    ParseFailed(&'static str),

    #[error(transparent)]
    SignatureError(#[from] p256::ecdsa::Error),

    #[error(transparent)]
    JsonError(#[from] serde_json::Error),

    #[error("Signing key error: {0}")]
    BadSigningKey(&'static str),

    #[error(transparent)]
    KmsError(#[from] kms::Error),

    #[error(transparent)]
    IoError(#[from] std::io::Error),
}
