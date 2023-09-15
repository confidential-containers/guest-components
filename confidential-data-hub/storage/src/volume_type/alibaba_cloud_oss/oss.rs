// Copyright (c) 2023 Intel
//
// SPDX-License-Identifier: Apache-2.0
//

use base64::{engine::general_purpose::STANDARD, Engine};
use secret::secret::Secret;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use crate::{Error, Result};

const OSSFS_PASSWD_FILE: &str = "/tmp/ossfs_passwd";
const GOCRYPTFS_PASSWD_FILE: &str = "/tmp/gocryptfs_passwd";
const OSSFS_BIN: &str = "/usr/local/bin/ossfs";
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
        .map_err(|e| Error::SecureMountFailed(format!("unseal failed: {e}")))?;
    Ok(res)
}

async fn get_plain(secret: &str) -> Result<String> {
    if secret.starts_with("sealed.") {
        let tmp = secret
            .strip_prefix("sealed.")
            .ok_or(Error::SecureMountFailed(
                "strip_prefix \"sealed.\" failed".to_string(),
            ))?;
        let unsealed = unseal_secret(tmp.into())
            .await
            .map_err(|e| Error::SecureMountFailed(format!("unseal secret failed: {e}")))?;

        return String::from_utf8(unsealed)
            .map_err(|e| Error::SecureMountFailed(format!("convert to String failed: {e}")));
    }
    Err(Error::SecureMountFailed(
        "sealed secret format error!".to_string(),
    ))
}

impl Oss {
    pub(crate) async fn mount(&self, source: String, mount_point: String) -> Result<String> {
        // unseal secret
        let plain_ak_id = get_plain(&self.ak_id)
            .await
            .map_err(|e| Error::SecureMountFailed(format!("get_plain failed: {e}")))?;
        let plain_ak_secret = get_plain(&self.ak_secret)
            .await
            .map_err(|e| Error::SecureMountFailed(format!("get_plain failed: {e}")))?;

        // create ossfs passwd file
        let mut ossfs_passwd = File::create(OSSFS_PASSWD_FILE)
            .map_err(|e| Error::SecureMountFailed(format!("create file failed: {e}")))?;
        let metadata = ossfs_passwd
            .metadata()
            .map_err(|e| Error::SecureMountFailed(format!("create metadata failed: {e}")))?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        ossfs_passwd
            .set_permissions(permissions)
            .map_err(|e| Error::SecureMountFailed(format!("set permissions failed: {e}")))?;
        ossfs_passwd
            .write_all(format!("{}:{}:{}", self.bucket, plain_ak_id, plain_ak_secret).as_bytes())
            .map_err(|e| Error::SecureMountFailed(format!("write file failed: {e}")))?;

        // generate parameters for ossfs command, and execute
        let mut opts = self
            .other_opts
            .split_whitespace()
            .map(str::to_string)
            .collect();
        let s = if self.encrypted == "gocryptfs" {
            "/tmp/oss/".to_string()
        } else {
            source.clone()
        };
        let mut parameters = vec![
            format!("{}:{}", self.bucket, self.path),
            s.clone(),
            format!("-ourl={}", self.url),
            format!("-opasswd_file={}", OSSFS_PASSWD_FILE),
        ];
        parameters.append(&mut opts);

        Command::new(OSSFS_BIN)
            .args(parameters)
            .spawn()
            .expect("failed to mount oss");
        std::thread::sleep(std::time::Duration::from_secs(3));

        // decrypt with gocryptfs if needed
        if self.encrypted == "gocryptfs" {
            // unseal secret
            let plain_passwd = get_plain(&self.enc_passwd)
                .await
                .map_err(|e| Error::SecureMountFailed(format!("get_plain failed: {e}")))?;

            // create gocryptfs passwd file
            let mut gocryptfs_passwd = File::create(GOCRYPTFS_PASSWD_FILE)
                .map_err(|e| Error::SecureMountFailed(format!("create file failed: {e}")))?;
            gocryptfs_passwd
                .write_all(plain_passwd.as_bytes())
                .map_err(|e| Error::SecureMountFailed(format!("write file failed: {e}")))?;

            // generate parameters for gocryptfs, and execute
            let parameters = vec![
                s,
                source,
                "-passfile".to_string(),
                GOCRYPTFS_PASSWD_FILE.to_string(),
                "-nosyslog".to_string(),
            ];
            Command::new(GOCRYPTFS_BIN)
                .args(parameters)
                .spawn()
                .expect("failed to decrypt oss");
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
        Ok(mount_point)
    }
}
