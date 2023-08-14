// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use confidential_data_hub::{hub::Hub, DataHub};
use log::debug;
use tokio::sync::RwLock;
use ttrpc::{asynchronous::TtrpcContext, Code, Error, Status};

use crate::{
    api::{GetResourceRequest, GetResourceResponse, UnsealSecretInput, UnsealSecretOutput},
    api_ttrpc::{GetResourceService, SealedSecretService},
};

pub struct Server {
    hub: Arc<RwLock<Hub>>,
}

impl Server {
    pub async fn new() -> Result<Self> {
        let hub = Arc::new(RwLock::new(Hub::new().await?));
        Ok(Self { hub })
    }
}

#[async_trait]
impl SealedSecretService for Server {
    async fn unseal_secret(
        &self,
        _ctx: &TtrpcContext,
        input: UnsealSecretInput,
    ) -> ::ttrpc::Result<UnsealSecretOutput> {
        debug!("get new UnsealSecret request");
        let hub = self.hub.clone();
        let reader = hub.read().await;
        let plaintext = reader.unseal_secret(input.secret).await.map_err(|e| {
            let mut status = Status::new();
            status.set_code(Code::INTERNAL);
            status.set_message(format!("[CDH] [ERROR]: Unseal Secret failed: {e}"));
            Error::RpcStatus(status)
        })?;

        let mut reply = UnsealSecretOutput::new();
        reply.plaintext = plaintext;
        debug!("send back plaintext of the sealed secret");
        Ok(reply)
    }
}
