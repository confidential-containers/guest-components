// Copyright (c) 2024 Intel
//
// SPDX-License-Identifier: Apache-2.0
//
use super::Interpreter;
use super::{get_plaintext_key, BlockDeviceError, BlockDeviceParameters, Result};
use async_trait::async_trait;
use log::error;
use rand::{distr::Alphanumeric, Rng};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

/// LUKS encrypt storage binary
const LUKS_ENCRYPT_STORAGE_BIN: &str = "/usr/local/bin/luks-encrypt-storage";

async fn random_encrypt_key() -> Vec<u8> {
    let mut buffer = vec![0u8; 4096];
    rand::rng().fill(&mut buffer[..]);
    buffer
}

async fn create_storage_key_file(
    storage_key_path: &str,
    encrypt_key: Option<String>,
) -> anyhow::Result<()> {
    let mut storage_key_file = fs::File::create(storage_key_path).await?;

    let plain_key = match encrypt_key {
        Some(encrypt_key) => get_plaintext_key(&encrypt_key).await?,
        None => random_encrypt_key().await,
    };

    storage_key_file.write_all(&plain_key).await?;
    storage_key_file.flush().await?;
    Ok(())
}

pub(crate) struct LuksInterpreter;

#[async_trait]
impl Interpreter for LuksInterpreter {
    async fn secure_device_mount(
        &self,
        parameters: BlockDeviceParameters,
        mount_point: &str,
    ) -> Result<()> {
        let random_string: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(5)
            .map(char::from)
            .collect();
        let storage_key_path = format!("/tmp/encrypted_storage_key_{}", random_string);
        create_storage_key_file(&storage_key_path, parameters.encryption_key.clone()).await?;

        let parameters = vec![
            parameters.device_id,
            match parameters.encryption_key {
                None => "false".to_string(),
                Some(_) => "true".to_string(),
            },
            mount_point.to_string(),
            storage_key_path,
            parameters.data_integrity.clone(),
        ];

        let mut encrypt_device = Command::new(LUKS_ENCRYPT_STORAGE_BIN)
            .args(parameters)
            .spawn()
            .map_err(|e| {
                error!("luks-encrypt-storage cmd fork failed: {:?}", e);
                BlockDeviceError::BlockDeviceMountFailed
            })?;

        let bd_res = encrypt_device.wait().await?;
        if !bd_res.success() {
            let mut stderr = String::new();
            if let Some(mut err) = encrypt_device.stderr.take() {
                err.read_to_string(&mut stderr).await?;
                error!("BlockDevice mount failed with stderr: {:?}", stderr);
            } else {
                error!("BlockDevice mount failed");
            }

            return Err(BlockDeviceError::BlockDeviceMountFailed);
        }
        Ok(())
    }
}
