// Copyright (c) 2023 Intel
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("secure mount failed: {0}")]
    SecureMountFailed(String),
}
