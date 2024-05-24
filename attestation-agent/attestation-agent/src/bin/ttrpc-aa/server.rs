// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use ::ttrpc::asynchronous::Service;
use ::ttrpc::proto::Code;
use anyhow::*;
use async_trait::async_trait;
use attestation_agent::{AttestationAPIs, AttestationAgent};
use log::{debug, error};
use tokio::sync::Mutex;

use std::collections::HashMap;
use std::sync::Arc;

use crate::ttrpc_protocol::attestation_agent::{
    CheckInitDataRequest, CheckInitDataResponse, ExtendRuntimeMeasurementRequest,
    ExtendRuntimeMeasurementResponse, GetEvidenceRequest, GetEvidenceResponse, GetTokenRequest,
    GetTokenResponse, UpdateConfigurationRequest, UpdateConfigurationResponse,
};
use crate::ttrpc_protocol::attestation_agent_ttrpc::{
    create_attestation_agent_service, AttestationAgentService,
};

pub const AGENT_NAME: &str = "attestation-agent";

pub struct AA {
    inner: Mutex<AttestationAgent>,
}

#[async_trait]
impl AttestationAgentService for AA {
    async fn get_token(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        req: GetTokenRequest,
    ) -> ::ttrpc::Result<GetTokenResponse> {
        debug!("AA (ttrpc): get token ...");

        let mut attestation_agent = self.inner.lock().await;

        let token = attestation_agent
            .get_token(&req.TokenType)
            .await
            .map_err(|e| {
                error!("AA (ttrpc): get token failed\n {e:?}");
                let mut error_status = ::ttrpc::proto::Status::new();
                error_status.set_code(Code::INTERNAL);
                error_status.set_message(format!("[ERROR:{AGENT_NAME}] AA-KBC get token failed"));
                ::ttrpc::Error::RpcStatus(error_status)
            })?;

        debug!("AA (ttrpc): Get token successfully!");

        let mut reply = GetTokenResponse::new();
        reply.Token = token;

        ::ttrpc::Result::Ok(reply)
    }

    async fn get_evidence(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        req: GetEvidenceRequest,
    ) -> ::ttrpc::Result<GetEvidenceResponse> {
        debug!("AA (ttrpc): get evidence ...");

        let mut attestation_agent = self.inner.lock().await;

        let evidence = attestation_agent
            .get_evidence(&req.RuntimeData)
            .await
            .map_err(|e| {
                error!("AA (ttrpc): get evidence failed:\n {e:?}");
                let mut error_status = ::ttrpc::proto::Status::new();
                error_status.set_code(Code::INTERNAL);
                error_status
                    .set_message(format!("[ERROR:{AGENT_NAME}] AA-KBC get evidence failed"));
                ::ttrpc::Error::RpcStatus(error_status)
            })?;

        debug!("AA (ttrpc): Get evidence successfully!");

        let mut reply = GetEvidenceResponse::new();
        reply.Evidence = evidence;

        ::ttrpc::Result::Ok(reply)
    }

    async fn extend_runtime_measurement(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        req: ExtendRuntimeMeasurementRequest,
    ) -> ::ttrpc::Result<ExtendRuntimeMeasurementResponse> {
        debug!("AA (ttrpc): extend runtime measurement ...");

        let mut attestation_agent = self.inner.lock().await;

        attestation_agent
            .extend_runtime_measurement(req.Events, req.RegisterIndex)
            .await
            .map_err(|e| {
                error!("AA (ttrpc): extend runtime measurement failed:\n {e:?}");
                let mut error_status = ::ttrpc::proto::Status::new();
                error_status.set_code(Code::INTERNAL);
                error_status.set_message(format!(
                    "[ERROR:{AGENT_NAME}] AA extend runtime measurement failed"
                ));
                ::ttrpc::Error::RpcStatus(error_status)
            })?;

        debug!("AA (ttrpc): extend runtime measurement succeeded.");
        let reply = ExtendRuntimeMeasurementResponse::new();
        ::ttrpc::Result::Ok(reply)
    }

    async fn check_init_data(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        req: CheckInitDataRequest,
    ) -> ::ttrpc::Result<CheckInitDataResponse> {
        debug!("AA (ttrpc): check initdata ...");

        let mut attestation_agent = self.inner.lock().await;

        attestation_agent
            .check_init_data(&req.Digest)
            .await
            .map_err(|e| {
                error!("AA (ttrpc): check initdata failed:\n {e:?}");
                let mut error_status = ::ttrpc::proto::Status::new();
                error_status.set_code(Code::INTERNAL);
                error_status.set_message(format!(
                    "[ERROR:{AGENT_NAME}] AA check initdata failed {e:?}"
                ));
                ::ttrpc::Error::RpcStatus(error_status)
            })?;

        debug!("AA (ttrpc): check initdata succeeded.");
        let reply = CheckInitDataResponse::new();
        ::ttrpc::Result::Ok(reply)
    }

    async fn update_configuration(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        req: UpdateConfigurationRequest,
    ) -> ::ttrpc::Result<UpdateConfigurationResponse> {
        debug!("AA (ttrpc): update configuration ...");

        let mut attestation_agent = self.inner.lock().await;

        attestation_agent
            .update_configuration(&req.config)
            .map_err(|e| {
                error!("AA (ttrpc): update configuration failed:\n {e:?}");
                let mut error_status = ::ttrpc::proto::Status::new();
                error_status.set_code(Code::INTERNAL);
                error_status.set_message(format!(
                    "[ERROR:{AGENT_NAME}] AA update configuration failed: {e:?}"
                ));
                ::ttrpc::Error::RpcStatus(error_status)
            })?;

        debug!("AA (ttrpc): update configuration succeeded.");
        let reply = UpdateConfigurationResponse::new();
        ::ttrpc::Result::Ok(reply)
    }
}

pub fn start_ttrpc_service(aa: AttestationAgent) -> Result<HashMap<String, Service>> {
    let service =
        Box::new(AA { inner: aa.into() }) as Box<dyn AttestationAgentService + Send + Sync>;

    let service = Arc::new(service);
    let get_resource_service = create_attestation_agent_service(service);
    Ok(get_resource_service)
}
