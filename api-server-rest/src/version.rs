// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::net::SocketAddr;

use anyhow::*;
use async_trait::async_trait;
use hyper::{Body, Method, Request, Response};

use crate::router::ApiHandler;

pub struct VersionClient {
    version: String,
}

impl VersionClient {
    pub fn new(version: &str) -> Self {
        Self {
            version: version.trim_end().to_string(),
        }
    }
}

#[async_trait]
impl ApiHandler for VersionClient {
    async fn handle_request(
        &self,
        _remote_addr: SocketAddr,
        _url_path: &str,
        req: Request<Body>,
    ) -> Result<Response<Body>> {
        if req.method() != Method::GET {
            return self.not_allowed();
        }
        Ok(Response::new(Body::from(self.version.clone())))
    }
}
