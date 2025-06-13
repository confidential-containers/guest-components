// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use ::ttrpc::proto::Code;
use async_trait::async_trait;
use attestation_agent::{AttestationAPIs, AttestationAgent};
use crypto::HashAlgorithm;
use kbs_types::TeePubKey;
use log::{debug, error};
use std::str::FromStr;

use crate::ttrpc_dep::ttrpc_protocol::{
    attestation_agent::{
        ExtendRuntimeMeasurementRequest, ExtendRuntimeMeasurementResponse,
        GetAdditionalEvidenceRequest, GetCompositeEvidenceRequest, GetEvidenceRequest,
        GetEvidenceResponse, GetTeeTypeRequest, GetTeeTypeResponse, GetTokenRequest,
        GetTokenResponse,
    },
    attestation_agent_ttrpc::AttestationAgentService,
};

#[allow(dead_code)]
pub const AGENT_NAME: &str = "attestation-agent";

#[allow(dead_code)]
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

    async fn get_additional_evidence(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        req: GetAdditionalEvidenceRequest,
    ) -> ::ttrpc::Result<GetEvidenceResponse> {
        debug!("AA (ttrpc): get evidence ...");

        let evidence = self
            .inner
            .get_additional_evidence(&req.RuntimeData)
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

    async fn get_composite_evidence(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        req: GetCompositeEvidenceRequest,
    ) -> ::ttrpc::Result<GetEvidenceResponse> {
        debug!("AA (ttrpc): get composite evidence ...");

        let tee_pubkey: TeePubKey = serde_json::from_str(&req.TeePubKey).map_err(|e| {
            error!("AA (ttrpc): get composite evidence failed:\n {e:?}");
            let mut error_status = ::ttrpc::proto::Status::new();
            error_status.set_code(Code::INTERNAL);
            error_status.set_message(format!(
                "[ERROR:{AGENT_NAME}] Failed to deserialize TeePubKey"
            ));
            ::ttrpc::Error::RpcStatus(error_status)
        })?;

        let hash_algorithm = HashAlgorithm::from_str(&req.HashAlgorithm).map_err(|e| {
            error!("AA (ttrpc): get composite evidence failed:\n {e:?}");
            let mut error_status = ::ttrpc::proto::Status::new();
            error_status.set_code(Code::INTERNAL);
            error_status.set_message(format!(
                "[ERROR:{AGENT_NAME}] Failed to deserialize hash algorithm"
            ));
            ::ttrpc::Error::RpcStatus(error_status)
        })?;

        let evidence = self
            .inner
            .get_composite_evidence(tee_pubkey, req.Nonce, hash_algorithm)
            .await
            .map_err(|e| {
                error!("AA (ttrpc): get composite evidence failed:\n {e:?}");
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
