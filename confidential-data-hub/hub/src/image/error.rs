// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

use crate::kms;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unknown WrapType: {0}")]
    UnknownWrapType(String),

    #[error("kms interface when {context}")]
    KmsError {
        #[source]
        source: kms::Error,
        context: &'static str,
    },

    #[error("base64 decoding failed when {context}")]
    Base64DecodeFailed {
        #[source]
        source: base64::DecodeError,
        context: &'static str,
    },

    #[error("decrypt LEK using KEK failed")]
    DecryptFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("malwared AnnotationPacket format")]
    ParseAnnotationPacket {
        #[source]
        source: anyhow::Error,
    },
}
