// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Get Rserouce gRPC client

use anyhow::*;
use async_trait::async_trait;
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

pub const GETRESOURCE_ADDR: &str = "http://127.0.0.1:50000";

pub struct Grpc {
    inner: GetResourceServiceClient<Channel>,
}

impl Grpc {
    pub async fn new() -> Result<Self> {
        let inner = GetResourceServiceClient::connect(GETRESOURCE_ADDR).await?;
        Ok(Self { inner })
    }
}

#[async_trait]
impl Client for Grpc {
    async fn get_resource(&mut self, resource_path: &str) -> Result<Vec<u8>> {
        let req = tonic::Request::new(GetResourceRequest {
            resource_path: resource_path.to_string(),
        });
        Ok(self.inner.get_resource(req).await?.into_inner().resource)
    }
}
