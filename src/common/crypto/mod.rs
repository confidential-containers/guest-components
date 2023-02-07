// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::str::FromStr;

use anyhow::*;
use zeroize::Zeroizing;

mod aes256ctr;
mod aes256gcm;

/// Supported WrapType, s.t. encryption algorithm using to encrypt the
/// [PLBCO](https://github.com/confidential-containers/attestation-agent/blob/main/docs/IMPLEMENTATION.md#encryption-and-decryption-of-container-image).
/// TODO: Support more kinds of en/decryption schemes.
#[derive(EnumString, AsRefStr)]
pub enum WrapType {
    /// The serialized name follows 5.2.6 section
    /// <https://www.rfc-editor.org/rfc/inline-errata/rfc7518.html>
    #[strum(serialize = "A256GCM")]
    Aes256Gcm,

    /// This type is not recommended as it is not AEAD.
    #[strum(serialize = "A256CTR")]
    Aes256Ctr,
}

type DecryptorFunc = Box<dyn Fn(&[u8], &[u8], &[u8]) -> Result<Vec<u8>>>;

impl From<WrapType> for DecryptorFunc {
    fn from(wt: WrapType) -> Self {
        match wt {
            WrapType::Aes256Gcm => Box::new(aes256gcm::decrypt),
            WrapType::Aes256Ctr => Box::new(aes256ctr::decrypt),
        }
    }
}

pub fn decrypt(
    key: Zeroizing<Vec<u8>>,
    ciphertext: Vec<u8>,
    iv: Vec<u8>,
    wrap_type: &str,
) -> Result<Vec<u8>> {
    let wrap_type = WrapType::from_str(wrap_type).context(format!(
        "Unsupported wrap type {wrap_type} when decrypt image layer",
    ))?;

    let decryptor: DecryptorFunc = wrap_type.into();
    let plaintext = decryptor(&ciphertext, &key, &iv)?;

    Ok(plaintext)
}
