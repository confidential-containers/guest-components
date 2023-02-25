// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Get Rserouce ttrpc client

use anyhow::*;
use async_trait::async_trait;
use ttrpc::context;

use super::Client;

use super::ttrpc_proto::getresource::GetResourceRequest;
use super::ttrpc_proto::getresource_ttrpc::GetResourceServiceClient;

const SOCKET_ADDR: &str = "unix:///opt/confidential-containers/attestation-agent/getresource.sock";

pub struct Ttrpc {
    gtclient: GetResourceServiceClient,
}

impl Ttrpc {
    pub fn new() -> Result<Self> {
        let inner = ttrpc::asynchronous::Client::connect(SOCKET_ADDR)?;
        let gtclient = GetResourceServiceClient::new(inner);

        Ok(Self { gtclient })
    }
}

#[async_trait]
impl Client for Ttrpc {
    async fn get_resource(&mut self, kbc_name: &str, resource_uri: &str) -> Result<Vec<u8>> {
        let req = GetResourceRequest {
            KbcName: kbc_name.to_string(),
            ResourceUri: resource_uri.to_string(),
            ..Default::default()
        };
        let res = self
            .gtclient
            .get_resource(context::with_timeout(20 * 1000 * 1000), &req)
            .await
            .context("ttrpc request error")?;
        Ok(res.Resource)
    }
}
