// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use attestation::attestation_agent_service_server::{
    AttestationAgentService, AttestationAgentServiceServer,
};
use attestation::{
    BindInitDataRequest, BindInitDataResponse, ExtendRuntimeMeasurementRequest,
    ExtendRuntimeMeasurementResponse, GetAdditionalEvidenceRequest, GetCompositeEvidenceRequest,
    GetEvidenceRequest, GetEvidenceResponse, GetTeeTypeRequest, GetTeeTypeResponse,
    GetTokenRequest, GetTokenResponse,
};
use attestation_agent::{AttestationAPIs, AttestationAgent};
use crypto::HashAlgorithm;
use kbs_types::TeePubKey;
use log::{debug, error};
use std::net::SocketAddr;
use std::str::FromStr;
use tonic::{transport::Server, Request, Response, Status};

mod attestation {
    tonic::include_proto!("attestation_agent");
}

pub const AGENT_NAME: &str = "attestation-agent";

pub struct AA {
    inner: AttestationAgent,
}

#[tonic::async_trait]
impl AttestationAgentService for AA {
    async fn get_token(
        &self,
        request: Request<GetTokenRequest>,
    ) -> Result<Response<GetTokenResponse>, Status> {
        let request = request.into_inner();

        debug!("AA (grpc): get token ...");

        let token = self
            .inner
            .get_token(&request.token_type)
            .await
            .map_err(|e| {
                error!("AA (grpc): get token failed:\n{e:?}");
                Status::internal(format!("[ERROR:{AGENT_NAME}] AA get token failed"))
            })?;

        debug!("AA (grpc): Get token successfully!");

        let reply = GetTokenResponse { token };

        Result::Ok(Response::new(reply))
    }

    async fn get_evidence(
        &self,
        request: Request<GetEvidenceRequest>,
    ) -> Result<Response<GetEvidenceResponse>, Status> {
        let request = request.into_inner();

        debug!("AA (grpc): get evidence ...");

        let evidence = self
            .inner
            .get_evidence(&request.runtime_data)
            .await
            .map_err(|e| {
                error!("AA (grpc): get evidence failed:\n{e:?}");
                Status::internal(format!("[ERROR:{AGENT_NAME}] AA get evidence failed"))
            })?;

        debug!("AA (grpc): Get evidence successfully!");

        let reply = GetEvidenceResponse { evidence };

        Result::Ok(Response::new(reply))
    }

    async fn get_additional_evidence(
        &self,
        request: Request<GetAdditionalEvidenceRequest>,
    ) -> Result<Response<GetEvidenceResponse>, Status> {
        let request = request.into_inner();

        debug!("AA (grpc): get additional evidence ...");

        let evidence = self
            .inner
            .get_additional_evidence(&request.runtime_data)
            .await
            .map_err(|e| {
                error!("AA (grpc): get additional evidence failed:\n{e:?}");
                Status::internal(format!(
                    "[ERROR:{AGENT_NAME}] AA get additional evidence failed"
                ))
            })?;

        debug!("AA (grpc): Get evidence successfully!");

        let reply = GetEvidenceResponse { evidence };

        Result::Ok(Response::new(reply))
    }

    async fn get_composite_evidence(
        &self,
        request: Request<GetCompositeEvidenceRequest>,
    ) -> Result<Response<GetEvidenceResponse>, Status> {
        let request = request.into_inner();

        debug!("AA (grpc): get composite evidence ...");

        let tee_pubkey: TeePubKey = serde_json::from_str(&request.tee_pub_key).map_err(|e| {
            error!("AA (grpc): get composite evidence failed:\n {e:?}");
            Status::internal(format!(
                "[ERROR:{AGENT_NAME}] Failed to deserialize Tee Pub Key"
            ))
        })?;

        let hash_algorithm = HashAlgorithm::from_str(&request.hash_algorithm).map_err(|e| {
            error!("AA (grpc): get composite evidence failed:\n {e:?}");
            Status::internal(format!(
                "[ERROR:{AGENT_NAME}] Failed to parse hash algorithm"
            ))
        })?;

        let evidence = self
            .inner
            .get_composite_evidence(tee_pubkey, request.nonce, hash_algorithm)
            .await
            .map_err(|e| {
                error!("AA (grpc): get composite evidence failed:\n{e:?}");
                Status::internal(format!(
                    "[ERROR:{AGENT_NAME}] AA get composite evidence failed"
                ))
            })?;

        debug!("AA (grpc): Get composite evidence successfully!");

        let reply = GetEvidenceResponse { evidence };

        Result::Ok(Response::new(reply))
    }

    async fn extend_runtime_measurement(
        &self,
        request: Request<ExtendRuntimeMeasurementRequest>,
    ) -> Result<Response<ExtendRuntimeMeasurementResponse>, Status> {
        let request = request.into_inner();

        debug!("AA (grpc): extend runtime measurement ...");

        self.inner
            .extend_runtime_measurement(
                &request.domain,
                &request.operation,
                &request.content,
                request.register_index,
            )
            .await
            .map_err(|e| {
                error!("AA (grpc): extend runtime measurement failed:\n{e:?}");
                Status::internal(format!(
                    "[ERROR:{AGENT_NAME}] AA extend runtime measurement failed"
                ))
            })?;

        debug!("AA (grpc): extend runtime measurement succeeded.");

        let reply = ExtendRuntimeMeasurementResponse {};

        Result::Ok(Response::new(reply))
    }

    async fn bind_init_data(
        &self,
        request: Request<BindInitDataRequest>,
    ) -> Result<Response<BindInitDataResponse>, Status> {
        let request = request.into_inner();

        debug!("AA (grpc): bind init data ...");

        self.inner
            .bind_init_data(&request.digest)
            .await
            .map_err(|e| {
                error!("AA (grpc): binding init data failed:\n{e:?}");
                Status::internal(format!("[ERROR:{AGENT_NAME}] AA binding init data failed"))
            })?;

        debug!("AA (grpc): init data binding successfully!");

        let reply = BindInitDataResponse {};

        Result::Ok(Response::new(reply))
    }

    async fn get_tee_type(
        &self,
        _request: Request<GetTeeTypeRequest>,
    ) -> Result<Response<GetTeeTypeResponse>, Status> {
        debug!("AA (grpc): get tee type ...");

        let tee = self.inner.get_tee_type();

        let tee = serde_json::to_string(&tee)
            .map_err(|e| {
                error!("AA (ttrpc): get tee type failed:\n {e:?}");
                Status::internal(format!("[ERROR:{AGENT_NAME}] AA get tee type failed"))
            })?
            .trim_end_matches('"')
            .trim_start_matches('"')
            .to_string();
        debug!("AA (ttrpc): get tee type succeeded.");

        let reply = GetTeeTypeResponse { tee };

        Result::Ok(Response::new(reply))
    }
}

pub async fn start_grpc_service(socket: SocketAddr, aa: AttestationAgent) -> Result<()> {
    let service = AA { inner: aa };
    Server::builder()
        .add_service(AttestationAgentServiceServer::new(service))
        .serve(socket)
        .await?;
    Ok(())
}
