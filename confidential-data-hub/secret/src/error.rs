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
}
