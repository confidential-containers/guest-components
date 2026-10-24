// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use attestation_agent::{
    AttestationAPIs, AttestationAgent, InitDataResult, RuntimeMeasurement,
    parse_init_data_algorithm,
};
use protos::grpc::aa::attestation_agent::{
    BindInitDataRequest, BindInitDataResponse, ExtendRuntimeMeasurementRequest,
    ExtendRuntimeMeasurementResponse, GetAdditionalEvidenceRequest, GetAdditionalTeesRequest,
    GetAdditionalTeesResponse, GetEvidenceRequest, GetEvidenceResponse, GetTeeTypeRequest,
    GetTeeTypeResponse, GetTokenRequest, GetTokenResponse, RuntimeMeasurementResult,
    attestation_agent_service_server::{AttestationAgentService, AttestationAgentServiceServer},
};
use std::net::SocketAddr;
use tonic::{Request, Response, Status, transport::Server};
use tracing::{debug, error};

pub const AGENT_NAME: &str = "attestation-agent";

/// Fixed message produced by the SE attester when the UV rejects the firmware flag.
const FIRMWARE_UNSUPPORTED_MSG: &str = "Firmware attestation requires z17 or later";

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
                // Surface this one actionable reason to the caller (shown in pod events).
                let reason = if format!("{e:?}").contains(FIRMWARE_UNSUPPORTED_MSG) {
                    format!(": {FIRMWARE_UNSUPPORTED_MSG}")
                } else {
                    String::new()
                };
                Status::internal(format!("[ERROR:{AGENT_NAME}] AA get token failed{reason}"))
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
                let reason = if format!("{e:?}").contains(FIRMWARE_UNSUPPORTED_MSG) {
                    format!(": {FIRMWARE_UNSUPPORTED_MSG}")
                } else {
                    String::new()
                };
                Status::internal(format!(
                    "[ERROR:{AGENT_NAME}] AA get evidence failed{reason}"
                ))
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
                let reason = if format!("{e:?}").contains(FIRMWARE_UNSUPPORTED_MSG) {
                    format!(": {FIRMWARE_UNSUPPORTED_MSG}")
                } else {
                    String::new()
                };
                Status::internal(format!(
                    "[ERROR:{AGENT_NAME}] AA get additional evidence failed{reason}"
                ))
            })?;

        debug!("AA (grpc): Get evidence successfully!");

        let reply = GetEvidenceResponse { evidence };

        Result::Ok(Response::new(reply))
    }

    async fn extend_runtime_measurement(
        &self,
        request: Request<ExtendRuntimeMeasurementRequest>,
    ) -> Result<Response<ExtendRuntimeMeasurementResponse>, Status> {
        let request = request.into_inner();

        debug!("AA (grpc): extend runtime measurement ...");

        let res = self
            .inner
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

        let reply = ExtendRuntimeMeasurementResponse {
            result: match res {
                RuntimeMeasurement::Ok => RuntimeMeasurementResult::Ok.into(),
                RuntimeMeasurement::NotSupported => RuntimeMeasurementResult::NotSupported.into(),
                RuntimeMeasurement::NotEnabled => RuntimeMeasurementResult::NotEnabled.into(),
            },
        };

        Result::Ok(Response::new(reply))
    }

    async fn bind_init_data(
        &self,
        request: Request<BindInitDataRequest>,
    ) -> Result<Response<BindInitDataResponse>, Status> {
        let request = request.into_inner();

        debug!("AA (grpc): bind init data ...");

        let alg = parse_init_data_algorithm(&request.algorithm, &request.digest).map_err(|e| {
            error!("AA (grpc): invalid init data algorithm: {e:?}");
            Status::invalid_argument(format!("[ERROR:{AGENT_NAME}] {e}"))
        })?;

        let result = self
            .inner
            .bind_init_data(&request.digest)
            .await
            .map_err(|e| {
                error!("AA (grpc): binding init data failed:\n{e:?}");
                Status::internal(format!("[ERROR:{AGENT_NAME}] AA binding init data failed"))
            })?;

        if let InitDataResult::NotBound = result {
            // Measuring the digest in the eventlog needs its hash algorithm.
            let Some(alg) = alg else {
                error!("AA (grpc): init data is not bound and no hash algorithm was given");
                return Err(Status::failed_precondition(format!(
                    "[ERROR:{AGENT_NAME}] AA init data is not bound: measuring it in the eventlog needs the hash algorithm"
                )));
            };
            self.inner
                .measure_init_data(alg, &request.digest)
                .await
                .map_err(|e| {
                    error!("AA (grpc): measuring init data failed:\n{e:?}");
                    Status::internal(format!(
                        "[ERROR:{AGENT_NAME}] AA measuring init data failed"
                    ))
                })?;
        }

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

    async fn get_additional_tees(
        &self,
        _request: Request<GetAdditionalTeesRequest>,
    ) -> Result<Response<GetAdditionalTeesResponse>, Status> {
        debug!("AA (grpc): get additional tees ...");

        let additional_tee = self.inner.get_additional_tees();

        let mut reply = GetAdditionalTeesResponse {
            additional_tees: vec![],
        };
        for tee in additional_tee {
            let tee = serde_json::to_string(&tee)
                .map_err(|e| {
                    error!("AA (grpc): get additional tees failed:\n{e:?}");
                    Status::internal(format!(
                        "[ERROR:{AGENT_NAME}] AA get additional tees failed"
                    ))
                })?
                .trim_end_matches('"')
                .trim_start_matches('"')
                .to_string();
            reply.additional_tees.push(tee);
        }
        debug!("AA (grpc): get additional tees succeeded.");
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
