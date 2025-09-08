// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Get Rserouce ttrpc client

use anyhow::*;
use async_trait::async_trait;
use tokio::sync::OnceCell;
use ttrpc::context;

use super::Client;

use super::ttrpc_proto::getresource::GetResourceRequest;
use super::ttrpc_proto::getresource_ttrpc::GetResourceServiceClient;

const SOCKET_ADDR: &str = "unix:///run/confidential-containers/cdh.sock";

#[derive(Default)]
pub struct Ttrpc {
    client: OnceCell<GetResourceServiceClient>,
}

#[async_trait]
impl Client for Ttrpc {
    async fn get_resource(&self, resource_path: &str) -> Result<Vec<u8>> {
        let req = GetResourceRequest {
            ResourcePath: resource_path.to_string(),
            ..Default::default()
        };

        let res = self
            .client
            .get_or_try_init(|| async {
                let inner = ttrpc::asynchronous::Client::connect(SOCKET_ADDR).await?;
                Ok(GetResourceServiceClient::new(inner))
            })
            .await?
            .get_resource(context::with_timeout(50 * 1000 * 1000 * 1000), &req)
            .await
            .context("ttrpc request error")?;
        Ok(res.Resource)
    }
}
