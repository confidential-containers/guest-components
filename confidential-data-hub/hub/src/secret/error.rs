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

    #[error("unseal envelope secret failed")]
    UnsealEnvelopeFailed(#[from] EnvelopeError),

    #[error("unseal vault secret failed")]
    UnsealVaultFailed(#[from] VaultError),

    #[error("parse SealedSecret failed: {0}")]
    ParseFailed(&'static str),

    #[error("Signature Error: {0}")]
    SignatureError(#[from] p256::ecdsa::Error),

    #[error("JSON Parsing Error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Signing key error: {0}")]
    BadSigningKey(&'static str),

    #[error("Failed to get key from KMS: {0}")]
    KmsError(#[from] kms::Error),

    #[error("IO Operation Failed: {0}")]
    IoError(#[from] std::io::Error),
}
