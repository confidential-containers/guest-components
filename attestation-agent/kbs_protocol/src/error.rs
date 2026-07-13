// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Attestation Agent evidence provider error: {0}")]
    AAEvidenceProvider(String),

    #[error("Attestation Agent token provider error: {0}")]
    AATokenProvider(String),

    #[error("decrypt KBS response body failed: {0}")]
    DecryptResponseFailed(String),

    #[error("get key pair failed: {0}")]
    GenerateKeyPairFailed(String),

    #[error("get evidence failed: {0}")]
    GetEvidence(String),

    #[error("get token failed: {0}")]
    GetTokenFailed(String),

    #[error("http request failed: {0}")]
    HttpError(String),

    #[error("KBS internal error: {0}")]
    KbsInternalError(String),

    #[error("deserialize http response failed: {0}")]
    KbsResponseDeserializationFailed(String),

    #[error("Native Evidence Provider error: {0}")]
    NativeEvidenceProvider(String),

    #[error("RCAR handshake failed: {0}")]
    RcarHandshake(String),

    #[error("KBS resource not found: {0}")]
    ResourceNotFound(String),

    #[error("request unauthorized")]
    UnAuthorized,

    #[error("invalid hash algorithm: {0}")]
    InvalidHashAlgorithm(String),

    #[error("unexpected JSON data type: expected {0}, got {1}")]
    UnexpectedJSONDataType(String, String),
}
