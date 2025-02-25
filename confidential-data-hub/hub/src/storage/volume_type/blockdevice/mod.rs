// Copyright (c) 2024 Intel
//
// SPDX-License-Identifier: Apache-2.0
//
pub mod error;
pub mod luks;

use super::SecureMount;
use crate::secret;
use async_trait::async_trait;
use error::{BlockDeviceError, Result};
use kms::{Annotations, ProviderSettings};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum::{Display, EnumString};

#[derive(EnumString, Serialize, Deserialize, Display, Debug, PartialEq, Eq)]
pub enum BlockDeviceEncryptType {
    #[strum(serialize = "luks")]
    LUKS,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct BlockDeviceParameters {
    /// The device number, formatted as "MAJ:MIN".
    #[serde(rename = "deviceId")]
    pub device_id: String,

    /// The encryption type. Currently, only LUKS is supported.
    #[serde(rename = "encryptType")]
    pub encryption_type: BlockDeviceEncryptType,

    /// Encryption key. If not set, generate a random 4096-byte key
    #[serde(rename = "encryptKey")]
    pub encryption_key: Option<String>,

    /// Indicates whether to enable dm-integrity.
    #[serde(rename = "dataIntegrity")]
    pub data_integrity: String,
}
pub(crate) struct BlockDevice;

#[async_trait]
pub trait Interpreter {
    async fn secure_device_mount(
        &self,
        parameters: BlockDeviceParameters,
        mount_point: &str,
    ) -> Result<()>;
}

async fn get_plaintext_key(resource: &str) -> anyhow::Result<Vec<u8>> {
    if resource.starts_with("sealed.") {
        debug!("detected sealed secret");
        let unsealed = secret::unseal_secret(resource.as_bytes()).await?;
        return Ok(unsealed);
    }

    if resource.starts_with("kbs://") {
        let secret = kms::new_getter("kbs", ProviderSettings::default())
            .await?
            .get_secret(resource, &Annotations::default())
            .await
            .map_err(|e| {
                error!("get keys from kbs failed: {e:?}");
                BlockDeviceError::GetKeysFailure(e.into())
            })?;
        return Ok(secret);
    }

    Err(BlockDeviceError::GetKeysFailure(anyhow::anyhow!("unknown resource scheme")).into())
}

impl BlockDevice {
    async fn real_mount(
        &self,
        options: &HashMap<String, String>,
        _flags: &[String],
        mount_point: &str,
    ) -> Result<()> {
        // construct BlockDeviceParameters
        let parameters = serde_json::to_string(options)?;
        let bd_parameter: BlockDeviceParameters = serde_json::from_str(&parameters)?;

        match bd_parameter.encryption_type {
            BlockDeviceEncryptType::LUKS => {
                luks::LuksInterpreter
                    .secure_device_mount(bd_parameter, mount_point)
                    .await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl SecureMount for BlockDevice {
    /// Mount the block device to the given `mount_point``.
    ///
    /// If `bd.encrypt_type` is set to `LUKS`, the device will be formated as a LUKS-encrypted device.
    /// Then use cryptsetup open the device and mount it to `mount_point` as plaintext.
    ///
    /// This is a wrapper for inner function to convert error type.
    async fn mount(
        &self,
        options: &HashMap<String, String>,
        flags: &[String],
        mount_point: &str,
    ) -> super::Result<()> {
        self.real_mount(options, flags, mount_point)
            .await
            .map_err(|e| e.into())
    }
}
