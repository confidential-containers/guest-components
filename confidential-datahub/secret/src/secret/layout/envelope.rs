// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub use kms::Annotations;

use crypto::WrapType;
use serde::{Deserialize, Serialize};

/// An Envelope is a secret encrypted by digital envelope mechanism.
/// It can be described as
///
/// {Enc(KMS, DEK), Enc(DEK, secret), paras...}
///
/// where Enc(A,B) means use key A to encrypt B
///
/// The fields inside this Struct will be flattened in a Secret wrapper.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Envelope {
    /// key id to locate the key inside KMS
    pub key_id: String,

    /// Encrypted DEK by key inside KMS
    pub encrypted_key: String,

    /// Encrypted data (secret) by DEK
    pub encrypted_data: String,

    /// Encryption scheme of the Encrypted data by DEK
    pub wrap_type: WrapType,

    /// IV of encrypted_data, if used
    pub iv: String,

    /// decryptor driver of the secret
    pub provider: String,

    /// KMS specific fields to locate the Key inside KMS
    pub annotations: Annotations,
}
