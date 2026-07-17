// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use protos::ttrpc::aa::attestation_agent::{
    ExtendRuntimeMeasurementRequest, GetAdditionalEvidenceRequest, GetAdditionalTeesRequest,
    GetEvidenceRequest, GetTeeTypeRequest, GetTokenRequest,
};
use protos::ttrpc::aa::attestation_agent_ttrpc::AttestationAgentServiceClient;
use serde::Deserialize;

use crate::client::ttrpc_client::CachedTtrpcClient;
use crate::TTRPC_TIMEOUT;

/// ROOT path for Confidential Data Hub API
pub const AA_ROOT: &str = "/aa";

/// URL for querying CDH get resource API
pub const AA_TOKEN_URL: &str = "/token";
pub const AA_EVIDENCE_URL: &str = "/evidence";
pub const AA_ADDITIONAL_EVIDENCE_URL: &str = "/additional-evidence";
pub const AA_AAEL_URL: &str = "/aael";

pub struct AAClient {
    client: CachedTtrpcClient<AttestationAgentServiceClient>,
}

#[derive(Deserialize)]
pub struct AaelEvent {
    pub domain: String,
    pub operation: String,
    pub content: String,
}

impl AAClient {
    pub async fn new(aa_addr: &str) -> Result<Self> {
        let client = CachedTtrpcClient::new(
            aa_addr,
            "Attestation Agent",
            AttestationAgentServiceClient::new,
        )
        .await?;

        Ok(Self { client })
    }

    pub async fn get_token(&self, token_type: &str) -> Result<Vec<u8>> {
        let res = self
            .client
            .call_with_retry(|client| async move {
                let req = GetTokenRequest {
                    TokenType: token_type.to_string(),
                    ..Default::default()
                };
                client
                    .get_token(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
                    .await
            })
            .await?;

        Ok(res.Token)
    }

    pub async fn get_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        let res = self
            .client
            .call_with_retry(|client| async move {
                let req = GetEvidenceRequest {
                    RuntimeData: runtime_data.to_vec(),
                    ..Default::default()
                };

                client
                    .get_evidence(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
                    .await
            })
            .await?;
        Ok(res.Evidence)
    }

    pub async fn get_additional_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        let res = self
            .client
            .call_with_retry(|client| async move {
                let req = GetAdditionalEvidenceRequest {
                    RuntimeData: runtime_data.to_vec(),
                    ..Default::default()
                };

                client
                    .get_additional_evidence(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
                    .await
            })
            .await?;
        Ok(res.Evidence)
    }

    pub async fn extend_aael_entry(
        &self,
        domain: &str,
        operation: &str,
        content: &str,
    ) -> Result<String> {
        let res = self
            .client
            .call_with_retry(|client| async move {
                let req = ExtendRuntimeMeasurementRequest {
                    Domain: domain.into(),
                    Operation: operation.into(),
                    Content: content.into(),
                    ..Default::default()
                };

                client
                    .extend_runtime_measurement(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
                    .await
            })
            .await?
            .Result
            .value();

        let res = match res {
            0 => "{\"success\":\"true\"}",
            1 => "{\"success\":\"false\",\"message\": \"The platform does not support runtime measurement\"}",
            2 => "{\"success\":\"false\",\"message\": \"Attestation Agent does not enable eventlog recording\"}",
            _ => "{\"success\":\"false\",\"message\": \"Unknown runtime measurement result\"}",
        };

        Ok(res.to_string())
    }

    pub async fn get_tee_type(&self) -> Result<String> {
        let res = self
            .client
            .call_with_retry(|client| async move {
                let req = GetTeeTypeRequest {
                    ..Default::default()
                };

                client
                    .get_tee_type(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
                    .await
            })
            .await?;
        Ok(res.tee)
    }

    pub async fn get_additional_tees(&self) -> Result<Vec<String>> {
        let res = self
            .client
            .call_with_retry(|client| async move {
                let req = GetAdditionalTeesRequest {
                    ..Default::default()
                };

                client
                    .get_additional_tees(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
                    .await
            })
            .await?;
        Ok(res.additional_tees)
    }
}
