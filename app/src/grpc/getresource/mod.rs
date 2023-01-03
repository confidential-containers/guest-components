// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use attestation_agent::AttestationAPIs;
use log::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};

use crate::grpc::AGENT_NAME;
use crate::ATTESTATION_AGENT;
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

        let attestation_agent_mutex_clone = Arc::clone(&ATTESTATION_AGENT);
        let mut attestation_agent = attestation_agent_mutex_clone.lock().await;

        debug!("Call AA-KBC to download resource ...");

        let target_resource = attestation_agent
            .download_confidential_resource(
                &request.kbc_name,
                &request.kbs_uri,
                &request.resource_description,
            )
            .await
            .map_err(|e| {
                error!("Call AA-KBC to get resource failed: {}", e);
                Status::internal(format!(
                    "[ERROR:{}] AA-KBC get resource failed: {}",
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
