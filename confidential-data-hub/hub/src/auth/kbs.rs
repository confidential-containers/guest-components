// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module helps to get confidential resources that will be used
//! by Confidential Data Hub from KBS, e.g. credentials used by KMSes.
//!
//! For the first implementation, it is assumed that all the resource
//! ids are from the kernel commandline in the following format:
//! ```
//! cdh.kbs_resources=<resource id 1>::<target path 1>,<resource id 2>::<target path 2>...
//! ```
//!
//! for example
//! ```
//! cdh.kbs_resources=kbs:///default/key/1::/run/temp1,kbs:///default/key/2::/run/temp2
//! ```
//!
//! TODO: update the way to pass the initial KBS resource list

use std::path::PathBuf;

use kms::{plugins::kbs::KbcClient, Annotations, Getter};
use tokio::fs;

use crate::{hub::Hub, Error, Result};

impl Hub {
    pub(crate) async fn init_kbs_resources() -> Result<()> {
        let cmdline = fs::read_to_string("/proc/cmdline")
            .await
            .map_err(|e| Error::InitializationFailed(format!("read kernel cmdline failed: {e}")))?;
        let kbs_resources = cmdline
            .split_ascii_whitespace()
            .find(|para| para.starts_with("cdh.kbs_resources="))
            .unwrap_or("cdh.kbs_resources=")
            .strip_prefix("cdh.kbs_resources=")
            .expect("must have one")
            .split(',')
            .filter(|s| !s.is_empty())
            .collect::<Vec<&str>>();

        let mut kbs_client = KbcClient::new()
            .await
            .map_err(|e| Error::InitializationFailed(format!("kbs client creation failed: {e}")))?;

        // for each `kbs://...::/...` string
        for resource_pair in kbs_resources {
            let s = resource_pair.split("::").collect::<Vec<&str>>();
            if s.len() != 2 {
                return Err(Error::InitializationFailed(format!(
                    "illegal `cdh.kbs_resources` item from kernel commandline: {resource_pair}"
                )));
            }

            let mut target_path = PathBuf::new();
            target_path.push(s[1]);
            let parent_dir = target_path
                .parent()
                .ok_or(Error::InitializationFailed(format!(
                    "illegal `cdh.kbs_resources` path item from kernel commandline: {}",
                    s[1]
                )))?;
            fs::create_dir_all(parent_dir).await.map_err(|e| {
                Error::InitializationFailed(format!(
                    "get kbs resource failed when creating dir: {e}"
                ))
            })?;

            let contents = kbs_client
                .get_secret(s[0], &Annotations::default())
                .await
                .map_err(|e| {
                    Error::InitializationFailed(format!("kbs client get resource failed: {e}"))
                })?;

            fs::write(target_path, contents).await.map_err(|e| {
                Error::InitializationFailed(format!(
                    "kbs client get resource failed when writing to file: {e}"
                ))
            })?;
        }

        Ok(())
    }
}
