// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod error;
pub mod secret;

use base64::{engine::general_purpose::STANDARD, Engine};

use crate::secret::Secret;

pub use error::*;
pub use kms::{Annotations, ProviderSettings};

/// The input sealed secret is in the following format
/// `sealed`.`JWS header`.`JWS body (secret content)`.`signature`
pub async fn unseal_secret(secret: &[u8]) -> Result<Vec<u8>> {
    let sections: Vec<_> = secret.split(|c| *c == b'.').collect();

    if sections.len() != 4 {
        return Err(SecretError::ParseFailed("malformed input sealed secret"));
    }

    if sections[0] != b"sealed" {
        return Err(SecretError::ParseFailed(
            "malformed input sealed secret. Without `sealed.` prefix",
        ));
    }

    let secret_json = STANDARD
        .decode(sections[2])
        .map_err(|_| SecretError::ParseFailed("base64 decode Secret body"))?;

    let secret: Secret = serde_json::from_slice(&secret_json).map_err(|_| {
        SecretError::ParseFailed(
            "malformed input sealed secret format (json deserialization failed)",
        )
    })?;

    secret.unseal().await
}
