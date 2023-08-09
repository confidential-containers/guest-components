// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("unseal envelope secret failed: {0}")]
    UnsealEnvelopeFailed(String),

    #[error("unseal vault secret failed: {0}")]
    UnsealVaultFailed(String),
}
