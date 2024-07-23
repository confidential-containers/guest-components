// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # Api definitions for KMS/Vault drivers
//!
//! To establish a connection between the client and the KMS/Vault server, two
//! kinds of parameters are required:
//! - Public parameters: like Region Id of the KMS/Vault, Instance Id of the KMS,
//! etc. They are not confidential and can be seen by anyone. [`ProviderSettings`]
//! is a json object. It is to include all the public parameters. The
//! hashmap style makes it flexible for different kinds of KMSes/Vaults. There
//! should be a function that takes a [`ProviderSettings`] as a input parameter
//! and returns a client instance.
//! - Private parameters: like the credential to access (e.g. access key).
//! These parameters should be captured inside the logic of `new()` rather
//! than the input parameter. it is strongly recommended that private parameters
//! be read from the encrypted filesystem, e.g. `/run/*` which is in TEE's
//! encrypted memory.
//!
//! ## APIs
//! - `Decrypter`: KMS's decrypt API.
//! - `Encrypter`: KMS's encrypt API.
//! - `Getter`: Vault's get secret API.
//! - `Setter`: Vault's set secret API.
//!
//! The rationality to distinguish these four different traits:
//! - `Decrypter` and `Getter` are used in-guest, while `Encrypter` and `Setter`
//! are used userside. They do not need to be implemented by a same object.

use crate::Result;

use async_trait::async_trait;
use serde_json::{Map, Value};

/// ProviderSettings are extra information to create a client
pub type ProviderSettings = Map<String, Value>;

/// Annotations is extra information of this encryption/decryption.
pub type Annotations = Map<String, Value>;

#[async_trait]
pub trait Decrypter: Send + Sync {
    /// Use the key of `key_id` to decrypt the `ciphertext` slice inside KMS, and then
    /// return the plaintext of the `data`. The decryption operation should occur
    /// inside KMS.
    async fn decrypt(
        &mut self,
        ciphertext: &[u8],
        key_id: &str,
        crypto_context: &Annotations,
    ) -> Result<Vec<u8>>;
}

#[async_trait]
pub trait Encrypter: Send + Sync {
    /// Use the key of `key_id` to encrypt the `data` slice inside KMS, and then
    /// return the ciphertext of the `data`. The encryption operation should occur
    /// inside KMS.
    ///
    /// The returned [`Annotations`] is the parameters of the encryption operation.
    async fn encrypt(&mut self, _data: &[u8], _key_id: &str) -> Result<(Vec<u8>, Annotations)>;
}

#[async_trait]
pub trait Setter: Send + Sync {
    /// Set secret. The `content` will be inserted with the key `name`.
    ///
    /// The returned [`Annotations`] is the parameters of the set operation.
    async fn set_secret(&mut self, _content: Vec<u8>, _name: String) -> Result<Annotations>;
}

#[async_trait]
pub trait Getter: Send + Sync {
    /// Get secret. Different secret manager will use different parameters inside
    /// `annotations`.
    async fn get_secret(&self, name: &str, annotations: &Annotations) -> Result<Vec<u8>>;
}
