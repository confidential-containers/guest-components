// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Get Rserouce native AA client

use anyhow::*;
use async_trait::async_trait;
use kbc::{cc_kbc::Kbc as CcKbc, sample_kbc::SampleKbc, KbcInterface};
use resource_uri::ResourceUri;

use super::Client;

enum Kbc {
    Sample(SampleKbc),
    Cc(CcKbc),
}

pub struct Native {
    inner: Kbc,
}

impl Native {
    pub fn new(decrypt_config: &Option<&str>) -> Result<Self> {
        let Some(wrapped_aa_kbc_params) = decrypt_config else {
            bail!("Secure channel creation needs aa_kbc_params.");
        };

        let aa_kbc_params = wrapped_aa_kbc_params.trim_start_matches("provider:attestation-agent:");

        let Some((kbc_name, kbs_uri)) = aa_kbc_params.split_once("::") else {
            bail!("illegal aa_kbc_params : {aa_kbc_params}");
        };

        if kbc_name.is_empty() {
            bail!("aa_kbc_params: missing KBC name");
        }

        if kbs_uri.is_empty() {
            bail!("aa_kbc_params: missing KBS URI");
        }

        let inner = match kbc_name {
            "cc_kbc" => Kbc::Cc(CcKbc::new(kbs_uri.to_owned())?),
            "sample_kbc" => Kbc::Sample(SampleKbc::new(kbs_uri.to_owned())),
            other => bail!("Unsupported KBC {other}"),
        };

        Ok(Self { inner })
    }
}

#[async_trait]
impl Client for Native {
    async fn get_resource(&mut self, resource_path: &str) -> Result<Vec<u8>> {
        let url =
            ResourceUri::try_from(resource_path).map_err(|e| anyhow!("parse ResourceUri: {e}"))?;
        let resource = match &mut self.inner {
            Kbc::Sample(ref mut inner) => inner.get_resource(url).await?,
            Kbc::Cc(ref mut inner) => inner.get_resource(url).await?,
        };
        Ok(resource)
    }
}
