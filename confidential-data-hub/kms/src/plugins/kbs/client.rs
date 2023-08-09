// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
use kbs_protocol::{
    client::KbsClient as KbsProtocolClient,
    token_provider::{AATokenProvider, TokenProvider},
    KbsClientCapabilities, ResourceUri,
};

use crate::{utils::get_kbs_host_from_cmdline, Annotations, Error, Getter, Result};

pub struct KbsClient {
    client: KbsProtocolClient<Box<dyn TokenProvider>>,
}

impl KbsClient {
    pub async fn new() -> Result<Self> {
        let kbs_host_url = get_kbs_host_from_cmdline().await?;

        let token_provider = AATokenProvider::new()
            .await
            .map_err(|e| Error::KbsClientError(format!("create AA token provider failed: {e}")))?;
        let client = kbs_protocol::KbsClientBuilder::with_token_provider(
            Box::new(token_provider),
            &kbs_host_url,
        )
        .build()
        .map_err(|e| Error::KbsClientError(format!("create kbs client failed: {e}")))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl Getter for KbsClient {
    async fn get_secret(&mut self, name: &str, _annotations: &Annotations) -> Result<Vec<u8>> {
        let resource_uri = ResourceUri::try_from(name).map_err(|e| {
            Error::KbsClientError(format!("get resource name must be a ResourceUri! {e}"))
        })?;
        let secret = self
            .client
            .get_resource(resource_uri)
            .await
            .map_err(|e| Error::KbsClientError(format!("get resource failed: {e}")))?;
        Ok(secret)
    }
}
