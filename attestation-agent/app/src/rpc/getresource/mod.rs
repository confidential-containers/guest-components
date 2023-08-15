// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use attestation_agent::AttestationAPIs;
use log::*;
use std::sync::Arc;

use crate::rpc::AGENT_NAME;

#[derive(Debug, Default)]
pub struct GetResource {}

#[cfg(feature = "grpc")]
pub mod grpc {
    use super::*;
    use crate::grpc::ASYNC_ATTESTATION_AGENT;
    use anyhow::*;
    use get_resource::get_resource_service_server::{GetResourceService, GetResourceServiceServer};
    use get_resource::{GetResourceRequest, GetResourceResponse};
    use std::net::SocketAddr;
    use tonic::{transport::Server, Request, Response, Status};

    mod get_resource {
        tonic::include_proto!("getresource");
    }

    #[tonic::async_trait]
    impl GetResourceService for GetResource {
        async fn get_resource(
            &self,
            request: Request<GetResourceRequest>,
        ) -> Result<Response<GetResourceResponse>, Status> {
            let request = request.into_inner();

            let attestation_agent_mutex_clone = Arc::clone(&ASYNC_ATTESTATION_AGENT);
            let mut attestation_agent = attestation_agent_mutex_clone.lock().await;

            debug!("Call AA-KBC to download resource ...");

            let target_resource = attestation_agent
                .download_confidential_resource(
                    &request.kbc_name,
                    &request.resource_path,
                    &request.kbs_uri,
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

    pub async fn start_grpc_service(socket: SocketAddr) -> Result<()> {
        let service = GetResource::default();
        Server::builder()
            .add_service(GetResourceServiceServer::new(service))
            .serve(socket)
            .await?;
        Ok(())
    }
}

#[cfg(feature = "ttrpc")]
pub mod ttrpc {
    use super::*;
    use crate::rpc::ttrpc_protocol::getresource_ttrpc::{
        create_get_resource_service, GetResourceService,
    };
    use crate::rpc::ttrpc_protocol::{getresource, getresource_ttrpc};
    use crate::ttrpc::ASYNC_ATTESTATION_AGENT;
    use ::ttrpc::asynchronous::Service;
    use ::ttrpc::proto::Code;
    use anyhow::*;
    use async_trait::async_trait;

    use std::collections::HashMap;

    #[async_trait]
    impl getresource_ttrpc::GetResourceService for GetResource {
        async fn get_resource(
            &self,
            _ctx: &::ttrpc::r#async::TtrpcContext,
            req: getresource::GetResourceRequest,
        ) -> ::ttrpc::Result<getresource::GetResourceResponse> {
            debug!("Call AA-KBC to download resource ...");

            let attestation_agent_mutex_clone = ASYNC_ATTESTATION_AGENT.clone();
            let mut attestation_agent = attestation_agent_mutex_clone.lock().await;

            let target_resource = attestation_agent
                .download_confidential_resource(&req.KbcName, &req.ResourcePath, &req.KbsUri)
                .await
                .map_err(|e| {
                    error!("Call AA-KBC to get resource failed: {}", e);
                    let mut error_status = ::ttrpc::proto::Status::new();
                    error_status.set_code(Code::INTERNAL);
                    error_status.set_message(format!(
                        "[ERROR:{}] AA-KBC get resource failed: {}",
                        AGENT_NAME, e
                    ));
                    ::ttrpc::Error::RpcStatus(error_status)
                })?;

            debug!("Get resource from KBS successfully!");

            let mut reply = getresource::GetResourceResponse::new();
            reply.Resource = target_resource;

            ::ttrpc::Result::Ok(reply)
        }
    }

    pub fn start_ttrpc_service() -> Result<HashMap<String, Service>> {
        let service = Box::new(GetResource {}) as Box<dyn GetResourceService + Send + Sync>;

        let service = Arc::new(service);
        let get_resource_service = create_get_resource_service(service);
        Ok(get_resource_service)
    }
}
