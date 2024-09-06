// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod auth_config;

use std::collections::HashMap;

use anyhow::*;
use oci_client::{secrets::RegistryAuth, Reference};
use serde::{Deserialize, Serialize};

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
    pub fn new(auth_file: &[u8]) -> Result<Self> {
        let docker_config_file: DockerConfigFile = serde_json::from_slice(auth_file)?;
        Ok(Self { docker_config_file })
    }

    /// Get a credential (RegistryAuth) for the given Reference.
    pub async fn credential_for_reference(&self, reference: &Reference) -> Result<RegistryAuth> {
        // TODO: support credential helpers
        auth_config::credential_from_auth_config(reference, &self.docker_config_file.auths)
    }
}
