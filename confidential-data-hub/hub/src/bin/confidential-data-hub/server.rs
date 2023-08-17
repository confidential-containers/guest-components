// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use confidential_data_hub::{hub::Hub, DataHub};
use lazy_static::lazy_static;
use log::debug;
use tokio::sync::RwLock;
use ttrpc::{asynchronous::TtrpcContext, Code, Error, Status};

use crate::{
    api::{GetResourceRequest, GetResourceResponse, UnsealSecretInput, UnsealSecretOutput},
    api_ttrpc::{GetResourceService, SealedSecretService},
};

lazy_static! {
    static ref HUB: Arc<RwLock<Option<Hub>>> = Arc::new(RwLock::new(None));
}

pub struct Server;

impl Server {
    async fn init() -> Result<()> {
        let mut writer = HUB.write().await;
        if writer.is_none() {
            let hub = Hub::new().await?;
            *writer = Some(hub);
        }

        Ok(())
    }

    pub async fn new() -> Result<Self> {
        Self::init().await?;
        Ok(Self)
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
        let reader = HUB.read().await;
        let reader = reader.as_ref().expect("must be initialized");
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

#[async_trait]
impl GetResourceService for Server {
    async fn get_resource(
        &self,
        _ctx: &TtrpcContext,
        req: GetResourceRequest,
    ) -> ::ttrpc::Result<GetResourceResponse> {
        debug!("get new GetResource request");
        let reader = HUB.read().await;
        let reader = reader.as_ref().expect("must be initialized");
        let resource = reader.get_resource(req.ResourcePath).await.map_err(|e| {
            let mut status = Status::new();
            status.set_code(Code::INTERNAL);
            status.set_message(format!("[CDH] [ERROR]: Get Resource failed: {e}"));
            Error::RpcStatus(status)
        })?;

        let mut reply = GetResourceResponse::new();
        reply.Resource = resource;
        debug!("send back the resource");
        Ok(reply)
    }
}
