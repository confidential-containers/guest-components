// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::router::ApiHandler;
use crate::ttrpc_proto::confidential_data_hub::GetResourceRequest;
use crate::ttrpc_proto::confidential_data_hub_ttrpc::GetResourceServiceClient;
use anyhow::*;
use async_trait::async_trait;
use hyper::{Body, Method, Request, Response};
use std::net::SocketAddr;

use crate::utils::split_nth_slash;
use crate::TTRPC_TIMEOUT;

/// ROOT path for Confidential Data Hub API
pub const CDH_ROOT: &str = "/cdh";

/// URL for querying CDH get resource API
pub const CDH_RESOURCE_URL: &str = "/resource";

const KBS_PREFIX: &str = "kbs://";

pub struct CDHClient {
    client: GetResourceServiceClient,
    accepted_method: Vec<Method>,
}

#[async_trait]
impl ApiHandler for CDHClient {
    async fn handle_request(
        &self,
        remote_addr: SocketAddr,
        url_path: &str,
        req: Request<Body>,
    ) -> Result<Response<Body>> {
        if !remote_addr.ip().is_loopback() {
            // Return 403 Forbidden response.
            return self.forbidden();
        }

        if !self.accepted_method.iter().any(|i| i.eq(&req.method())) {
            // Return 405 Method Not Allowed response.
            return self.not_allowed();
        }

        if let Some((api, resource_path)) = split_nth_slash(url_path, 2) {
            match api {
                CDH_RESOURCE_URL => match self.get_resource(resource_path).await {
                    std::result::Result::Ok(results) => return self.octet_stream_response(results),
                    Err(e) => return self.internal_error(e.to_string()),
                },
                _ => {
                    return self.not_found();
                }
            }
        }

        Ok(Response::builder().status(404).body(Body::empty())?)
    }
}

impl CDHClient {
    pub fn new(cdh_addr: &str, accepted_method: Vec<Method>) -> Result<Self> {
        let inner = ttrpc::asynchronous::Client::connect(cdh_addr)
            .context(format!("ttrpc connect to CDH addr: {} failed!", cdh_addr))?;
        let client = GetResourceServiceClient::new(inner);

        Ok(Self {
            client,
            accepted_method,
        })
    }

    pub async fn get_resource(&self, resource_path: &str) -> Result<Vec<u8>> {
        let req = GetResourceRequest {
            ResourcePath: format!("{}{}", KBS_PREFIX, resource_path),
            ..Default::default()
        };
        let res = self
            .client
            .get_resource(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.Resource)
    }
}
