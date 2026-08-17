// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Get Resource native AA client

use anyhow::*;
use async_trait::async_trait;
use kbc::{
    cc_kbc::Kbc as CcKbc, offline_fs_kbc::OfflineFsKbc, sample_kbc::SampleKbc, KbcInterface,
};
use resource_uri::ResourceUri;
use tokio::sync::Mutex;

use super::Client;

enum Kbc {
    Sample(SampleKbc),
    OfflineFs(OfflineFsKbc),
    Cc(CcKbc),
}

pub struct Native {
    inner: Mutex<Kbc>,
}

impl Native {
    pub fn new(kbc_name: &str, kbs_uri: &str) -> Result<Self> {
        if kbc_name.is_empty() {
            bail!("aa_kbc_params: missing KBC name");
        }

        let inner = match kbc_name {
            "cc_kbc" => {
                if kbs_uri.is_empty() {
                    bail!("aa_kbc_params: missing KBS URI");
                }
                Kbc::Cc(CcKbc::new(kbs_uri.to_owned())?)
            }
            "sample_kbc" => {
                if kbs_uri.is_empty() {
                    bail!("aa_kbc_params: missing KBS URI");
                }
                Kbc::Sample(SampleKbc::new(kbs_uri.to_owned()))
            }
            "offline_fs_kbc" => Kbc::OfflineFs(OfflineFsKbc::new()),
            other => bail!("Unsupported KBC {other}"),
        };

        let inner = Mutex::new(inner);
        Ok(Self { inner })
    }
}

#[async_trait]
impl Client for Native {
    async fn get_resource(&self, resource_path: &str) -> Result<Vec<u8>> {
        let url =
            ResourceUri::try_from(resource_path).map_err(|e| anyhow!("parse ResourceUri: {e}"))?;
        let resource = match *self.inner.lock().await {
            Kbc::Sample(ref mut inner) => inner.get_resource(url).await?,
            Kbc::OfflineFs(ref mut inner) => inner.get_resource(url).await?,
            Kbc::Cc(ref mut inner) => inner.get_resource(url).await?,
        };
        Ok(resource)
    }
}
