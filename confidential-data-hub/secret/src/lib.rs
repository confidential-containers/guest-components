// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod error;
pub mod secret;

use crate::secret::Secret;

pub use error::*;
pub use kms::{Annotations, ProviderSettings};

/// The input sealed secret is in the following format
/// `sealed`.`JWS header`.`JWS body (secret content)`.`signature`
pub async fn unseal_secret(secret: &[u8]) -> Result<Vec<u8>> {
    let secret_string = String::from_utf8(secret.to_vec())
        .map_err(|_| SecretError::ParseFailed("Secret string must be UTF-8"))?;

    let secret = Secret::from_signed_base64_string(secret_string)?;
    secret.unseal().await
}
