// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use log::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};

use crate::grpc::AGENT_NAME;
use crate::kbc_runtime;
use get_resource::get_resource_service_server::{GetResourceService, GetResourceServiceServer};
use get_resource::{GetResourceRequest, GetResourceResponse};

pub mod get_resource {
    tonic::include_proto!("getresource");
}

#[derive(Debug, Default)]
pub struct GetResource {}

#[tonic::async_trait]
impl GetResourceService for GetResource {
    async fn get_resource(
        &self,
        request: Request<GetResourceRequest>,
    ) -> Result<Response<GetResourceResponse>, Status> {
        let request = request.into_inner();

        let kbc_runtime_mutex_clone = Arc::clone(&kbc_runtime::KBC_RUNTIME);
        let mut kbc_runtime = kbc_runtime_mutex_clone.lock().map_err(|e| {
            error!("Get KBC runtime MUTEX failed: {}", e);
            Status::internal(format!(
                "[ERROR:{}] Get KBC runtime failed: {}",
                AGENT_NAME, e
            ))
        })?;

        debug!("Call KBC to download resource ...");

        let target_resource = kbc_runtime
            .get_resource(
                request.kbc_name,
                request.kbs_uri,
                request.resource_description,
            )
            .map_err(|e| {
                error!("Call KBC to get resource failed: {}", e);
                Status::internal(format!(
                    "[ERROR:{}] KBC get resource failed: {}",
                    AGENT_NAME, e
                ))
            })?;

        debug!("Get resource from KBS successfully!");

        let reply = GetResourceResponse {
            resource: target_resource,
        };

        Result::Ok(Response::new(reply))
    }
}

pub async fn start_service(socket: SocketAddr) -> Result<()> {
    let service = GetResource::default();
    let _server = Server::builder()
        .add_service(GetResourceServiceServer::new(service))
        .serve(socket)
        .await?;
    Ok(())
}
