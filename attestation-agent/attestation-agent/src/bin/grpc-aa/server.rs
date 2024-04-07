// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use attestation::attestation_agent_service_server::{
    AttestationAgentService, AttestationAgentServiceServer,
};
use attestation::{
    ExtendRuntimeMeasurementRequest, ExtendRuntimeMeasurementResponse, GetEvidenceRequest,
    GetEvidenceResponse, GetTokenRequest, GetTokenResponse,
};
use attestation_agent::{AttestationAPIs, AttestationAgent};
use log::{debug, error};
use std::net::SocketAddr;
use tokio::sync::Mutex;
use tonic::{transport::Server, Request, Response, Status};

use self::attestation::{CheckInitDataRequest, CheckInitDataResponse};

mod attestation {
    tonic::include_proto!("attestation_agent");
}

pub const AGENT_NAME: &str = "attestation-agent";

pub struct AA {
    inner: Mutex<AttestationAgent>,
}

#[tonic::async_trait]
impl AttestationAgentService for AA {
    async fn get_token(
        &self,
        request: Request<GetTokenRequest>,
    ) -> Result<Response<GetTokenResponse>, Status> {
        let request = request.into_inner();

        let mut attestation_agent = self.inner.lock().await;

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

        let mut attestation_agent = self.inner.lock().await;

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

        let mut attestation_agent = self.inner.lock().await;

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

    async fn check_init_data(
        &self,
        request: Request<CheckInitDataRequest>,
    ) -> Result<Response<CheckInitDataResponse>, Status> {
        let request = request.into_inner();

        let mut attestation_agent = self.inner.lock().await;

        debug!("Call AA to check init data ...");

        attestation_agent
            .check_init_data(&request.digest)
            .await
            .map_err(|e| {
                error!("Call AA to check init data failed: {}", e);
                Status::internal(format!(
                    "[ERROR:{}] AA check init data failed: {}",
                    AGENT_NAME, e
                ))
            })?;

        debug!("Check init data successfully!");

        let reply = CheckInitDataResponse {};

        Result::Ok(Response::new(reply))
    }
}

pub async fn start_grpc_service(socket: SocketAddr, aa: AttestationAgent) -> Result<()> {
    let service = AA { inner: aa.into() };
    Server::builder()
        .add_service(AttestationAgentServiceServer::new(service))
        .serve(socket)
        .await?;
    Ok(())
}
