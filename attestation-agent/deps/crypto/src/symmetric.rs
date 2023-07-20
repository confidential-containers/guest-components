// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! APIs for symmetric keys

use std::str::FromStr;

use anyhow::*;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[cfg(feature = "openssl")]
use crate::native::*;

#[cfg(all(feature = "rust-crypto", not(feature = "openssl")))]
use crate::rust::*;

/// Supported WrapType, s.t. encryption algorithm using to encrypt the
/// [PLBCO](https://github.com/confidential-containers/guest-components/blob/main/attestation-agent/docs/IMPLEMENTATION.md#encryption-and-decryption-of-container-image).
/// TODO: Support more kinds of en/decryption schemes.
#[derive(EnumString, AsRefStr, Serialize, Deserialize, PartialEq, Debug)]
pub enum WrapType {
    /// The serialized name follows 5.2.6 section
    /// <https://www.rfc-editor.org/rfc/inline-errata/rfc7518.html>
    #[strum(serialize = "A256GCM")]
    #[serde(rename = "A256GCM")]
    Aes256Gcm,

    /// This type is not recommended as it is not AEAD.
    #[strum(serialize = "A256CTR")]
    #[serde(rename = "A256CTR")]
    Aes256Ctr,
}

/// Decrypt the given `ciphertext`.
/// Note:
/// - IV length for A256GCM: 12 bytes
/// - IV length for A256CTR: 16 bytes
pub fn decrypt(
    key: Zeroizing<Vec<u8>>,
    ciphertext: Vec<u8>,
    iv: Vec<u8>,
    wrap_type: &str,
) -> Result<Vec<u8>> {
    let wrap_type = WrapType::from_str(wrap_type).context(format!(
        "Unsupported wrap type {wrap_type} when decrypt image layer",
    ))?;

    match wrap_type {
        WrapType::Aes256Gcm => aes256gcm::decrypt(&ciphertext, &key, &iv),
        WrapType::Aes256Ctr => aes256ctr::decrypt(&ciphertext, &key, &iv),
    }
}

/// Encrypt the given `plaintext`.
/// Note:
/// - IV length for A256GCM: 12 bytes
/// - IV length for A256CTR: 16 bytes
pub fn encrypt(
    key: Zeroizing<Vec<u8>>,
    plaintext: Vec<u8>,
    iv: Vec<u8>,
    wrap_type: &str,
) -> Result<Vec<u8>> {
    let wrap_type = WrapType::from_str(wrap_type).context(format!(
        "Unsupported wrap type {wrap_type} when decrypt image layer",
    ))?;

    match wrap_type {
        WrapType::Aes256Gcm => aes256gcm::encrypt(&plaintext, &key, &iv),
        WrapType::Aes256Ctr => aes256ctr::encrypt(&plaintext, &key, &iv),
    }
}
