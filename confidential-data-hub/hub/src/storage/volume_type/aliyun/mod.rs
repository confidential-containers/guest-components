// Copyright (c) 2023 Intel
// Copyright (c) 2024 Alibaba
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod error;

use std::{collections::HashMap, os::unix::fs::PermissionsExt};

use anyhow::Context;
use async_trait::async_trait;
use log::{debug, error};
use rand::{distr::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

use crate::secret;
use error::{AliyunError, Result};

use super::SecureMount;

/// Name of the file that contains ossfs password
const OSSFS_PASSWD_FILE: &str = "ossfs_passwd";

/// Name of the file that contains gocryptfs password
const GOCRYPTFS_PASSWD_FILE: &str = "gocryptfs_passwd";

/// Aliyun OSS filesystem client binary
const OSSFS_BIN: &str = "/usr/local/bin/ossfs";

/// Gocryptofs binary
const GOCRYPTFS_BIN: &str = "/usr/local/bin/gocryptfs";

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct OssParameters {
    #[serde(rename = "akId")]
    pub ak_id: String,
    #[serde(rename = "akSecret")]
    pub ak_secret: String,
    #[serde(default)]
    pub annotations: String,
    pub bucket: String,
    #[serde(default)]
    pub encrypted: String,
    #[serde(rename = "encPasswd", default)]
    pub enc_passwd: String,
    #[serde(rename = "kmsKeyId", default)]
    pub kms_key_id: String,
    #[serde(rename = "otherOpts")]
    pub other_opts: String,
    pub path: String,
    pub readonly: String,
    #[serde(rename = "targetPath")]
    pub target_path: String,
    pub url: String,
    #[serde(rename = "volumeId")]
    pub volume_id: String,
}

pub(crate) struct Oss;

async fn get_plaintext_secret(secret: &str) -> anyhow::Result<String> {
    if secret.starts_with("sealed.") {
        debug!("detected sealed secret");
        let unsealed = secret::unseal_secret(secret.as_bytes()).await?;

        String::from_utf8(unsealed).context("convert to String failed")
    } else {
        Ok(secret.into())
    }
}

async fn create_random_dir() -> anyhow::Result<String> {
    const NAME_LENGTH: usize = 10;

    let name: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(NAME_LENGTH)
        .map(char::from)
        .collect();

    let path_name = format!("/tmp/{name}");
    fs::create_dir_all(&path_name)
        .await
        .context("create /tmp dir")?;
    Ok(path_name)
}

impl Oss {
    async fn real_mount(
        &self,
        options: &HashMap<String, String>,
        _flags: &[String],
        mount_point: &str,
    ) -> Result<()> {
        // construct OssParameters
        let parameters = serde_json::to_string(options)?;

        let oss_parameter: OssParameters = serde_json::from_str(&parameters)?;

        // unseal secret
        let plain_ak_id = get_plaintext_secret(&oss_parameter.ak_id).await?;
        let plain_ak_secret = get_plaintext_secret(&oss_parameter.ak_secret).await?;

        // create temp directory to store metadata for this mount operation
        let tempdir = tempfile::tempdir()?;

        // create ossfs passwd file
        let mut ossfs_passwd_path = tempdir.path().to_owned();
        ossfs_passwd_path.push(OSSFS_PASSWD_FILE);
        let ossfs_passwd_path = ossfs_passwd_path.to_string_lossy().to_string();
        let mut ossfs_passwd = fs::File::create(&ossfs_passwd_path).await?;
        let mut permissions = ossfs_passwd.metadata().await?.permissions();
        permissions.set_mode(0o600);
        ossfs_passwd.set_permissions(permissions).await?;
        ossfs_passwd
            .write_all(
                format!(
                    "{}:{}:{}",
                    oss_parameter.bucket, plain_ak_id, plain_ak_secret
                )
                .as_bytes(),
            )
            .await?;
        ossfs_passwd.sync_all().await?;
        drop(ossfs_passwd);

        // generate parameters for ossfs command
        let mut opts = oss_parameter
            .other_opts
            .split_whitespace()
            .map(str::to_string)
            .collect();

        if oss_parameter.encrypted == "gocryptfs" {
            let gocryptfs_dir = create_random_dir().await?;

            let mut parameters = vec![
                format!("{}:{}", oss_parameter.bucket, oss_parameter.path),
                gocryptfs_dir.clone(),
                format!("-ourl={}", oss_parameter.url),
                format!("-opasswd_file={ossfs_passwd_path}"),
            ];

            parameters.append(&mut opts);
            let mut oss = Command::new(OSSFS_BIN)
                .args(parameters)
                .spawn()
                .map_err(|e| {
                    error!("oss cmd fork failed: {e:?}");
                    AliyunError::OssfsMountFailed
                })?;
            let oss_res = oss.wait().await?;
            if !oss_res.success() {
                {
                    let mut stderr = String::new();
                    if let Some(mut err) = oss.stderr {
                        err.read_to_string(&mut stderr).await?;
                        error!("OSS mount failed with stderr: {stderr}");
                    } else {
                        error!("OSS mount failed");
                    }

                    return Err(AliyunError::OssfsMountFailed);
                }
            }

            // get the gocryptfs password
            let plain_passwd = get_plaintext_secret(&oss_parameter.enc_passwd).await?;

            // create gocryptfs passwd file
            let mut gocryptfs_passwd_path = tempdir.path().to_owned();
            gocryptfs_passwd_path.push(GOCRYPTFS_PASSWD_FILE);
            let gocryptfs_passwd_path = gocryptfs_passwd_path.to_string_lossy().to_string();
            let mut gocryptfs_passwd = fs::File::create(&gocryptfs_passwd_path).await?;

            gocryptfs_passwd.write_all(plain_passwd.as_bytes()).await?;
            gocryptfs_passwd.sync_all().await?;
            drop(gocryptfs_passwd);

            // generate parameters for gocryptfs, and execute
            let parameters = vec![
                gocryptfs_dir,
                mount_point.to_string(),
                "-passfile".to_string(),
                gocryptfs_passwd_path,
                "-nosyslog".to_string(),
            ];
            let mut gocryptfs = Command::new(GOCRYPTFS_BIN)
                .args(parameters)
                .spawn()
                .map_err(|_| AliyunError::GocryptfsMountFailed)?;

            let gocryptfs_res = gocryptfs.wait().await?;
            if !gocryptfs_res.success() {
                {
                    let mut stderr = String::new();

                    if let Some(mut err) = gocryptfs.stderr {
                        err.read_to_string(&mut stderr).await?;
                        error!("gocryptfs failed with stderr: {stderr}");
                    } else {
                        error!("gocryptfs failed");
                    }
                    return Err(AliyunError::GocryptfsMountFailed);
                }
            }
        } else {
            let mut parameters = vec![
                format!("{}:{}", oss_parameter.bucket, oss_parameter.path),
                mount_point.to_string(),
                format!("-ourl={}", oss_parameter.url),
                format!("-opasswd_file={ossfs_passwd_path}"),
            ];

            parameters.append(&mut opts);
            let mut oss = Command::new(OSSFS_BIN)
                .args(parameters)
                .spawn()
                .map_err(|e| {
                    error!("oss cmd fork failed: {e:?}");
                    AliyunError::OssfsMountFailed
                })?;
            let oss_res = oss.wait().await?;
            if !oss_res.success() {
                {
                    let mut stderr = String::new();
                    if let Some(mut err) = oss.stderr {
                        err.read_to_string(&mut stderr).await?;
                        error!("oss mount failed with stderr: {stderr}");
                    } else {
                        error!("oss mount failed");
                    }
                    return Err(AliyunError::OssfsMountFailed);
                }
            }
        };

        Ok(())
    }
}

#[async_trait]
impl SecureMount for Oss {
    /// Mount the Aliyun OSS storage to the given `mount_point``.
    ///
    /// If `oss.encrypted` is set to `gocryptfs`, the OSS storage is a gocryptofs FUSE.
    /// This function will create a temp directory, which is used to mount OSS. Then
    /// use gocryptfs to mount the `mount_point` as plaintext and the temp directory
    /// as ciphertext.
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
