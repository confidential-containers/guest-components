// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Convert AnnotationPacket failed: {0}")]
    ConvertAnnotationPacketFailed(String),

    #[error("unwrap key failed (Annotation V1): {0}")]
    UnwrapAnnotationV1Failed(String),

    #[error("unwrap key failed (Annotation V2): {0}")]
    UnwrapAnnotationV2Failed(String),
}
