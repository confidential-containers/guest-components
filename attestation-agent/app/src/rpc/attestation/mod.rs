// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use attestation_agent::AttestationAPIs;
use log::*;
use std::sync::Arc;

use crate::rpc::AGENT_NAME;

#[derive(Debug, Default)]
pub struct Attestation {}

#[cfg(feature = "grpc")]
pub mod grpc {
    use super::*;
    use crate::grpc::ASYNC_ATTESTATION_AGENT;
    use anyhow::*;
    use attestation::attestation_agent_service_server::{
        AttestationAgentService, AttestationAgentServiceServer,
    };
    use attestation::{
        ExtendRuntimeMeasurementRequest, ExtendRuntimeMeasurementResponse, GetEvidenceRequest,
        GetEvidenceResponse, GetTokenRequest, GetTokenResponse,
    };
    use std::net::SocketAddr;
    use tonic::{transport::Server, Request, Response, Status};

    mod attestation {
        tonic::include_proto!("attestation_agent");
    }

    #[tonic::async_trait]
    impl AttestationAgentService for Attestation {
        async fn get_token(
            &self,
            request: Request<GetTokenRequest>,
        ) -> Result<Response<GetTokenResponse>, Status> {
            let request = request.into_inner();

            let attestation_agent_mutex_clone = Arc::clone(&ASYNC_ATTESTATION_AGENT);
            let mut attestation_agent = attestation_agent_mutex_clone.lock().await;

            debug!("Call AA to get token ...");

            let token = attestation_agent
                .get_token(&request.token_type)
                .await
                .map_err(|e| {
                    error!("Call AA to get token failed: {}", e);
                    Status::internal(format!("[ERROR:{}] AA get token failed: {}", AGENT_NAME, e))
                })?;

            debug!("Get token successfully!");

            let reply = GetTokenResponse { token };

            Result::Ok(Response::new(reply))
        }

        async fn get_evidence(
            &self,
            request: Request<GetEvidenceRequest>,
        ) -> Result<Response<GetEvidenceResponse>, Status> {
            let request = request.into_inner();

            let attestation_agent_mutex_clone = Arc::clone(&ASYNC_ATTESTATION_AGENT);
            let mut attestation_agent = attestation_agent_mutex_clone.lock().await;

            debug!("Call AA to get evidence ...");

            let evidence = attestation_agent
                .get_evidence(&request.runtime_data)
                .await
                .map_err(|e| {
                    error!("Call AA to get evidence failed: {}", e);
                    Status::internal(format!(
                        "[ERROR:{}] AA get evidence failed: {}",
                        AGENT_NAME, e
                    ))
                })?;

            debug!("Get evidence successfully!");

            let reply = GetEvidenceResponse { evidence };

            Result::Ok(Response::new(reply))
        }

        async fn extend_runtime_measurement(
            &self,
            request: Request<ExtendRuntimeMeasurementRequest>,
        ) -> Result<Response<ExtendRuntimeMeasurementResponse>, Status> {
            let request = request.into_inner();

            let attestation_agent_mutex_clone = Arc::clone(&ASYNC_ATTESTATION_AGENT);
            let mut attestation_agent = attestation_agent_mutex_clone.lock().await;

            debug!("Call AA to extend runtime measurement ...");

            attestation_agent
                .extend_runtime_measurement(request.events, request.register_index)
                .await
                .map_err(|e| {
                    error!("Call AA to extend runtime measurement failed: {}", e);
                    Status::internal(format!(
                        "[ERROR:{}] AA extend runtime measurement failed: {}",
                        AGENT_NAME, e
                    ))
                })?;

            debug!("Extend runtime measurement successfully!");

            let reply = ExtendRuntimeMeasurementResponse {};

            Result::Ok(Response::new(reply))
        }
    }

    pub async fn start_grpc_service(socket: SocketAddr) -> Result<()> {
        let service = Attestation::default();
        Server::builder()
            .add_service(AttestationAgentServiceServer::new(service))
            .serve(socket)
            .await?;
        Ok(())
    }
}

#[cfg(feature = "ttrpc")]
pub mod ttrpc {
    use super::*;
    use crate::rpc::ttrpc_protocol::attestation_agent_ttrpc::{
        create_attestation_agent_service, AttestationAgentService,
    };
    use crate::rpc::ttrpc_protocol::{attestation_agent, attestation_agent_ttrpc};
    use crate::ttrpc::ASYNC_ATTESTATION_AGENT;
    use ::ttrpc::asynchronous::Service;
    use ::ttrpc::proto::Code;
    use anyhow::*;
    use async_trait::async_trait;

    use std::collections::HashMap;

    #[async_trait]
    impl attestation_agent_ttrpc::AttestationAgentService for Attestation {
        async fn get_token(
            &self,
            _ctx: &::ttrpc::r#async::TtrpcContext,
            req: attestation_agent::GetTokenRequest,
        ) -> ::ttrpc::Result<attestation_agent::GetTokenResponse> {
            debug!("Call AA to get token ...");

            let attestation_agent_mutex_clone = ASYNC_ATTESTATION_AGENT.clone();
            let mut attestation_agent = attestation_agent_mutex_clone.lock().await;

            let token = attestation_agent
                .get_token(&req.TokenType)
                .await
                .map_err(|e| {
                    error!("Call AA-KBC to get token failed: {}", e);
                    let mut error_status = ::ttrpc::proto::Status::new();
                    error_status.set_code(Code::INTERNAL);
                    error_status.set_message(format!(
                        "[ERROR:{}] AA-KBC get token failed: {}",
                        AGENT_NAME, e
                    ));
                    ::ttrpc::Error::RpcStatus(error_status)
                })?;

            debug!("Get token successfully!");

            let mut reply = attestation_agent::GetTokenResponse::new();
            reply.Token = token;

            ::ttrpc::Result::Ok(reply)
        }

        async fn get_evidence(
            &self,
            _ctx: &::ttrpc::r#async::TtrpcContext,
            req: attestation_agent::GetEvidenceRequest,
        ) -> ::ttrpc::Result<attestation_agent::GetEvidenceResponse> {
            debug!("Call AA to get evidence ...");

            let attestation_agent_mutex_clone = ASYNC_ATTESTATION_AGENT.clone();
            let mut attestation_agent = attestation_agent_mutex_clone.lock().await;

            let evidence = attestation_agent
                .get_evidence(&req.RuntimeData)
                .await
                .map_err(|e| {
                    error!("Call AA-KBC to get evidence failed: {}", e);
                    let mut error_status = ::ttrpc::proto::Status::new();
                    error_status.set_code(Code::INTERNAL);
                    error_status.set_message(format!(
                        "[ERROR:{}] AA-KBC get evidence failed: {}",
                        AGENT_NAME, e
                    ));
                    ::ttrpc::Error::RpcStatus(error_status)
                })?;

            debug!("Get evidence successfully!");

            let mut reply = attestation_agent::GetEvidenceResponse::new();
            reply.Evidence = evidence;

            ::ttrpc::Result::Ok(reply)
        }

        async fn extend_runtime_measurement(
            &self,
            _ctx: &::ttrpc::r#async::TtrpcContext,
            req: attestation_agent::ExtendRuntimeMeasurementRequest,
        ) -> ::ttrpc::Result<attestation_agent::ExtendRuntimeMeasurementResponse> {
            debug!("Call AA to extend runtime measurement ...");

            let attestation_agent_mutex_clone = ASYNC_ATTESTATION_AGENT.clone();
            let mut attestation_agent = attestation_agent_mutex_clone.lock().await;

            attestation_agent
                .extend_runtime_measurement(req.Events, req.RegisterIndex)
                .await
                .map_err(|e| {
                    error!("Call AA to extend runtime measurement failed: {}", e);
                    let mut error_status = ::ttrpc::proto::Status::new();
                    error_status.set_code(Code::INTERNAL);
                    error_status.set_message(format!(
                        "[ERROR:{}] AA extend runtime measurement failed: {}",
                        AGENT_NAME, e
                    ));
                    ::ttrpc::Error::RpcStatus(error_status)
                })?;

            let reply = attestation_agent::ExtendRuntimeMeasurementResponse::new();
            ::ttrpc::Result::Ok(reply)
        }
    }

    pub fn start_ttrpc_service() -> Result<HashMap<String, Service>> {
        let service = Box::new(Attestation {}) as Box<dyn AttestationAgentService + Send + Sync>;

        let service = Arc::new(service);
        let get_resource_service = create_attestation_agent_service(service);
        Ok(get_resource_service)
    }
}
