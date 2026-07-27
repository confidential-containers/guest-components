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

/// AAEL domain reserved for events recorded by the guest components
/// themselves, e.g. the `PullImage` event that CDH records for every image it
/// pulls. See
/// <https://github.com/confidential-containers/trustee/blob/main/kbs/docs/confidential-containers-eventlog.md#confidential-containers-event-spec>
const RESERVED_AAEL_DOMAIN: &str = "github.com/confidential-containers";

/// Whether `domain` belongs to the namespace reserved for the guest components.
///
/// AAEL entries carry no producer identity, so a relying party cannot tell a
/// `PullImage` event recorded by CDH apart from a byte-identical one appended
/// by the workload. This endpoint is the workload-facing surface, so it must
/// not be able to speak for the components: the workload could otherwise claim
/// to be running an image it never pulled. The components reach AA over its
/// ttrpc socket directly and are unaffected.
pub fn is_reserved_aael_domain(domain: &str) -> bool {
    domain == RESERVED_AAEL_DOMAIN || domain.starts_with(&format!("{RESERVED_AAEL_DOMAIN}/"))
}

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

#[cfg(test)]
mod tests {
    use super::is_reserved_aael_domain;
    use rstest::rstest;

    #[rstest]
    #[case("github.com/confidential-containers", true)]
    #[case("github.com/confidential-containers/cdh", true)]
    #[case("github.com/confidential-container", false)]
    #[case("github.com/confidential-containers-evil", false)]
    #[case("example.com", false)]
    #[case("", false)]
    fn test_is_reserved_aael_domain(#[case] domain: &str, #[case] reserved: bool) {
        assert_eq!(is_reserved_aael_domain(domain), reserved);
    }
}
