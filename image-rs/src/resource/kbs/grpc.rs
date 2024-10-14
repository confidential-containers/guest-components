// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Get Rserouce gRPC client

use anyhow::*;
use async_trait::async_trait;
use tokio::sync::{Mutex, OnceCell};
use tonic::transport::Channel;

use self::get_resource::{
    get_resource_service_client::GetResourceServiceClient, GetResourceRequest,
};

use super::Client;

mod get_resource {
    #![allow(unknown_lints)]
    #![allow(clippy::derive_partial_eq_without_eq)]
    #![allow(clippy::redundant_async_block)]
    tonic::include_proto!("api");
}

pub const _GETRESOURCE_ADDR: &str = "http://127.0.0.1:50000";

#[derive(Default)]
pub struct Grpc {
    client: OnceCell<Mutex<GetResourceServiceClient<Channel>>>,
}

#[async_trait]
impl Client for Grpc {
    async fn get_resource(&self, resource_path: &str) -> Result<Vec<u8>> {
        let req = tonic::Request::new(GetResourceRequest {
            resource_path: resource_path.to_string(),
        });

        let resource = self
            .client
            .get_or_try_init(|| async {
                let client = GetResourceServiceClient::connect(_GETRESOURCE_ADDR).await?;
                Ok(Mutex::new(client))
            })
            .await?
            .lock()
            .await
            .get_resource(req)
            .await?
            .into_inner()
            .resource;
        Ok(resource)
    }
}
