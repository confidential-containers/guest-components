// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use ::ttrpc::proto::Code;
use async_trait::async_trait;
use attestation_agent::{AttestationAPIs, AttestationAgent};
use log::{debug, error};

use crate::ttrpc_dep::ttrpc_protocol::{
    attestation_agent::{
        ExtendRuntimeMeasurementRequest, ExtendRuntimeMeasurementResponse, GetDerivedKeyRequest,
        GetDerivedKeyResponse, GetEvidenceRequest, GetEvidenceResponse, GetTeeTypeRequest,
        GetTeeTypeResponse, GetTokenRequest, GetTokenResponse, UpdateConfigurationRequest,
        UpdateConfigurationResponse,
    },
    attestation_agent_ttrpc::AttestationAgentService,
};

pub const AGENT_NAME: &str = "attestation-agent";

pub struct AA {
    pub(crate) inner: AttestationAgent,
}

#[async_trait]
impl AttestationAgentService for AA {
    async fn get_token(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        req: GetTokenRequest,
    ) -> ::ttrpc::Result<GetTokenResponse> {
        debug!("AA (ttrpc): get token ...");

        let token = self.inner.get_token(&req.TokenType).await.map_err(|e| {
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

        let evidence = self
            .inner
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

    async fn get_derived_key(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        req: GetDerivedKeyRequest,
    ) -> ::ttrpc::Result<GetDerivedKeyResponse> {
        debug!("AA (ttrpc): get derived key ...");

        let key_id: [u8; 1] = [0];
        let derived_key = self
            .inner
            .get_derived_key(&key_id, Vec::new())
            .await
            .map_err(|e| {
                error!(
                    "AA (ttrpc): get derived key failed:\n {e:?}\n key_id:\n {:#?}",
                    &key_id
                );
                let mut error_status = ::ttrpc::proto::Status::new();
                error_status.set_code(Code::INTERNAL);
                error_status.set_message(format!(
                    "[ERROR:{AGENT_NAME}] AA-KBC get derived key failed. key_id: {:#?}",
                    &key_id
                ));
                ::ttrpc::Error::RpcStatus(error_status)
            })?;

        debug!("AA (ttrpc): Get derived key successfully!");

        let mut reply = GetDerivedKeyResponse::new();
        reply.DerivedKey = derived_key;

        ::ttrpc::Result::Ok(reply)
    }

    async fn extend_runtime_measurement(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        req: ExtendRuntimeMeasurementRequest,
    ) -> ::ttrpc::Result<ExtendRuntimeMeasurementResponse> {
        debug!("AA (ttrpc): extend runtime measurement ...");

        self.inner
            .extend_runtime_measurement(
                &req.Domain,
                &req.Operation,
                &req.Content,
                req.RegisterIndex,
            )
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

    async fn update_configuration(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        req: UpdateConfigurationRequest,
    ) -> ::ttrpc::Result<UpdateConfigurationResponse> {
        debug!("AA (ttrpc): update configuration ...");

        self.inner
            .update_configuration(&req.config)
            .await
            .map_err(|e| {
                error!("AA (ttrpc): update configuration failed:\n {e:?}");
                let mut error_status = ::ttrpc::proto::Status::new();
                error_status.set_code(Code::INTERNAL);
                error_status.set_message(format!(
                    "[ERROR:{AGENT_NAME}] AA update configuration failed"
                ));
                ::ttrpc::Error::RpcStatus(error_status)
            })?;

        debug!("AA (ttrpc): update configuration succeeded.");
        let reply = UpdateConfigurationResponse::new();
        ::ttrpc::Result::Ok(reply)
    }

    async fn get_tee_type(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        _req: GetTeeTypeRequest,
    ) -> ::ttrpc::Result<GetTeeTypeResponse> {
        debug!("AA (ttrpc): get tee type ...");

        let tee = self.inner.get_tee_type();

        let res = serde_json::to_string(&tee)
            .map_err(|e| {
                error!("AA (ttrpc): get tee type failed:\n {e:?}");
                let mut error_status = ::ttrpc::proto::Status::new();
                error_status.set_code(Code::INTERNAL);
                error_status
                    .set_message(format!("[ERROR:{AGENT_NAME}] AA-KBC get tee type failed"));
                ::ttrpc::Error::RpcStatus(error_status)
            })?
            .trim_end_matches('"')
            .trim_start_matches('"')
            .to_string();
        debug!("AA (ttrpc): get tee type succeeded.");
        let mut reply = GetTeeTypeResponse::new();
        reply.tee = res;
        ::ttrpc::Result::Ok(reply)
    }
}
