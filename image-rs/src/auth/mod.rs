// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod auth_config;

use std::collections::HashMap;

use oci_client::{secrets::RegistryAuth, Reference};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type AuthResult<T> = std::result::Result<T, AuthError>;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid registry auth file")]
    InvalidRegistryAuthFile,
}

#[derive(Deserialize, Serialize, Default)]
pub struct DockerConfigFile {
    auths: HashMap<String, DockerAuthConfig>,
    // TODO: support credential helpers
}

#[derive(Deserialize, Serialize, Default)]
pub struct DockerAuthConfig {
    auth: String,
}

#[derive(Default)]
pub struct Auth {
    docker_config_file: DockerConfigFile,
}

impl Auth {
    pub fn new(auth_file: &[u8]) -> AuthResult<Self> {
        let docker_config_file: DockerConfigFile =
            serde_json::from_slice(auth_file).map_err(|_| AuthError::InvalidRegistryAuthFile)?;
        Ok(Self { docker_config_file })
    }

    /// Get a credential (RegistryAuth) for the given Reference.
    pub async fn credential_for_reference(
        &self,
        reference: &Reference,
    ) -> AuthResult<RegistryAuth> {
        // TODO: support credential helpers
        auth_config::credential_from_auth_config(reference, &self.docker_config_file.auths)
    }
}
