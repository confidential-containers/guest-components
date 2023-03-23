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
        let _server = Server::builder()
            .add_service(GetResourceServiceServer::new(service))
            .serve(socket)
            .await?;
        Ok(())
    }
}

#[cfg(feature = "ttrpc")]
pub mod ttrpc {
    use super::*;
    use crate::rpc::ttrpc_protocol::{getresource, getresource_ttrpc};
    use crate::rpc::TtrpcService;
    use crate::ttrpc::SYNC_ATTESTATION_AGENT;
    use ::ttrpc::proto::Code;
    use futures::executor::block_on;

    impl getresource_ttrpc::GetResourceService for GetResource {
        fn get_resource(
            &self,
            _ctx: &::ttrpc::TtrpcContext,
            req: getresource::GetResourceRequest,
        ) -> ::ttrpc::Result<getresource::GetResourceResponse> {
            let attestation_agent_mutex_clone = Arc::clone(&SYNC_ATTESTATION_AGENT);
            let mut attestation_agent = attestation_agent_mutex_clone.lock().map_err(|e| {
                let mut error_status = ::ttrpc::proto::Status::new();
                error_status.set_code(Code::INTERNAL);
                error_status.set_message(format!(
                    "[ERROR:{}] AA-KBC get mutex lock: {}",
                    AGENT_NAME, e
                ));
                ::ttrpc::Error::RpcStatus(error_status)
            })?;

            debug!("Call AA-KBC to download resource ...");

            let target_resource = block_on(attestation_agent.download_confidential_resource(
                &req.KbcName,
                &req.ResourcePath,
                &req.KbsUri,
            ))
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

    pub fn ttrpc_service() -> TtrpcService {
        getresource_ttrpc::create_get_resource_service(Arc::new(Box::new(GetResource {})
            as Box<dyn getresource_ttrpc::GetResourceService + Send + Sync>))
    }
}
