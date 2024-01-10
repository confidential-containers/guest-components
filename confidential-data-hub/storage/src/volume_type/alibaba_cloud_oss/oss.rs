// Copyright (c) 2023 Intel
//
// SPDX-License-Identifier: Apache-2.0
//

use std::os::unix::fs::PermissionsExt;

use base64::{engine::general_purpose::STANDARD, Engine};
use log::debug;
use secret::secret::Secret;
use serde::{Deserialize, Serialize};
use tokio::{fs, io::AsyncWriteExt, process::Command};

use crate::{Error, Result};

/// Name of the file that contains ossfs password
const OSSFS_PASSWD_FILE: &str = "ossfs_passwd";

/// Name of the file that contains gocryptfs password
const GOCRYPTFS_PASSWD_FILE: &str = "gocryptfs_passwd";

/// Aliyun OSS filesystem client binary
const OSSFS_BIN: &str = "/usr/local/bin/ossfs";

/// Gocryptofs binary
const GOCRYPTFS_BIN: &str = "/usr/local/bin/gocryptfs";

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Oss {
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

async fn unseal_secret(secret: Vec<u8>) -> Result<Vec<u8>> {
    // TODO: verify the jws signature using the key specified by `kid`
    // in header. Here we directly get the JWS payload
    let payload = secret.split(|c| *c == b'.').nth(1).ok_or_else(|| {
        Error::SecureMountFailed("illegal input sealed secret (not a JWS)".into())
    })?;

    let secret_json = STANDARD.decode(payload).map_err(|e| {
        Error::SecureMountFailed(format!(
            "illegal input sealed secret (JWS body is not standard base64 encoded): {e}"
        ))
    })?;
    let secret: Secret = serde_json::from_slice(&secret_json).map_err(|e| {
        Error::SecureMountFailed(format!(
            "illegal input sealed secret format (json deseralization failed): {e}"
        ))
    })?;

    let res = secret
        .unseal()
        .await
        .map_err(|e| Error::UnsealSecretFailed(format!("unseal failed: {e}")))?;
    Ok(res)
}

async fn get_plaintext_secret(secret: &str) -> Result<String> {
    if secret.starts_with("sealed.") {
        debug!("detected sealed secret");
        let tmp = secret
            .strip_prefix("sealed.")
            .ok_or(Error::SecureMountFailed(
                "strip_prefix \"sealed.\" failed".to_string(),
            ))?;
        let unsealed = unseal_secret(tmp.into()).await?;

        String::from_utf8(unsealed)
            .map_err(|e| Error::SecureMountFailed(format!("convert to String failed: {e}")))
    } else {
        Ok(secret.into())
    }
}

impl Oss {
    /// Mount the Aliyun OSS storage to the given `mount_point``.
    ///
    /// The OSS parameters of the mount source are stored inside the `Oss` struct.
    ///
    /// If `oss.encrypted` is set to `gocryptfs`, the OSS storage is a gocryptofs FUSE.
    /// This function will create a temp directory, which is used to mount OSS. Then
    /// use gocryptfs to mount the `mount_point` as plaintext and the temp directory
    /// as ciphertext.
    pub(crate) async fn mount(&self, _source: String, mount_point: String) -> Result<String> {
        // unseal secret
        let plain_ak_id = get_plaintext_secret(&self.ak_id).await?;
        let plain_ak_secret = get_plaintext_secret(&self.ak_secret).await?;

        // create temp directory to storage metadata for this mount operation
        let tempdir = tempfile::tempdir().map_err(|e| {
            Error::FileError(format!(
                "create ossfs metadata temp directory failed: {e:?}"
            ))
        })?;

        // create ossfs passwd file
        let mut ossfs_passwd_path = tempdir.path().to_owned();
        ossfs_passwd_path.push(OSSFS_PASSWD_FILE);
        let ossfs_passwd_path = ossfs_passwd_path.to_string_lossy().to_string();
        let mut ossfs_passwd = fs::File::create(&ossfs_passwd_path)
            .await
            .map_err(|e| Error::FileError(format!("create ossfs password file failed: {e:?}")))?;
        let mut permissions = ossfs_passwd
            .metadata()
            .await
            .map_err(|e| Error::FileError(format!("create metadata failed: {e}")))?
            .permissions();
        permissions.set_mode(0o600);
        ossfs_passwd
            .set_permissions(permissions)
            .await
            .map_err(|e| Error::FileError(format!("set permissions failed: {e}")))?;
        ossfs_passwd
            .write_all(format!("{}:{}:{}", self.bucket, plain_ak_id, plain_ak_secret).as_bytes())
            .await
            .map_err(|e| Error::FileError(format!("write file failed: {e}")))?;

        // generate parameters for ossfs command
        let mut opts = self
            .other_opts
            .split_whitespace()
            .map(str::to_string)
            .collect();

        if self.encrypted == "gocryptfs" {
            let gocryptfs_dir = tempfile::tempdir().map_err(|e| {
                Error::FileError(format!("create gocryptfs mount dir failed: {e:?}"))
            })?;

            let gocryptfs_dir_path = gocryptfs_dir.path().to_string_lossy().to_string();
            let mut parameters = vec![
                format!("{}:{}", self.bucket, self.path),
                gocryptfs_dir_path.clone(),
                format!("-ourl={}", self.url),
                format!("-opasswd_file={ossfs_passwd_path}"),
            ];

            parameters.append(&mut opts);
            Command::new(OSSFS_BIN)
                .args(parameters)
                .spawn()
                .map_err(|e| Error::SecureMountFailed(format!("failed to mount oss: {e:?}")))?;

            // get the gocryptfs password
            let plain_passwd = get_plaintext_secret(&self.enc_passwd).await?;

            // create gocryptfs passwd file
            let mut gocryptfs_passwd_path = tempdir.path().to_owned();
            gocryptfs_passwd_path.push(GOCRYPTFS_PASSWD_FILE);
            let gocryptfs_passwd_path = gocryptfs_passwd_path.to_string_lossy().to_string();
            let mut gocryptfs_passwd =
                fs::File::create(&gocryptfs_passwd_path)
                    .await
                    .map_err(|e| {
                        Error::FileError(format!("create gocryptfs password file failed: {e:?}"))
                    })?;

            gocryptfs_passwd
                .write_all(plain_passwd.as_bytes())
                .await
                .map_err(|e| Error::FileError(format!("write file failed: {e}")))?;

            // generate parameters for gocryptfs, and execute
            let parameters = vec![
                gocryptfs_dir_path,
                mount_point.clone(),
                "-passfile".to_string(),
                gocryptfs_passwd_path,
                "-nosyslog".to_string(),
            ];
            Command::new(GOCRYPTFS_BIN)
                .args(parameters)
                .spawn()
                .map_err(|e| Error::SecureMountFailed(format!("failed to decrypt oss: {e:?}")))?;
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        } else {
            let mut parameters = vec![
                format!("{}:{}", self.bucket, self.path),
                mount_point.clone(),
                format!("-ourl={}", self.url),
                format!("-opasswd_file={ossfs_passwd_path}"),
            ];

            parameters.append(&mut opts);
            Command::new(OSSFS_BIN)
                .args(parameters)
                .spawn()
                .map_err(|e| Error::SecureMountFailed(format!("failed to mount oss: {e:?}")))?;
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        };

        Ok(mount_point)
    }
}
