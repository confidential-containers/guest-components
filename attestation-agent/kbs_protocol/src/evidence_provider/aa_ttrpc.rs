// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
use attester::TeeEvidence;
use kbs_types::Tee;
use serde_json::json;
use ttrpc::context;

use crate::{Error, Result};
use protos::ttrpc::aa::{
    attestation_agent::{
        GetAdditionalEvidenceRequest, GetEvidenceRequest, GetTeeMetadataRequest, GetTeeTypeRequest,
    },
    attestation_agent_ttrpc::AttestationAgentServiceClient,
};

use super::{EvidenceProvider, TeeInfo, TotalTeeInfo};

const AA_SOCKET_FILE: &str =
    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

/// The timeout for ttrpc call to Attestation Agent
const AA_TTRPC_TIMEOUT_SECONDS: i64 = 50;

pub struct AAEvidenceProvider {
    client: AttestationAgentServiceClient,
}

impl AAEvidenceProvider {
    pub async fn new() -> Result<Self> {
        let c = ttrpc::r#async::Client::connect(AA_SOCKET_FILE)
            .await
            .map_err(|e| Error::AATokenProvider(format!("ttrpc connect failed {e}")))?;
        let client = AttestationAgentServiceClient::new(c);
        Ok(Self { client })
    }
}

#[async_trait]
impl EvidenceProvider for AAEvidenceProvider {
    /// Get evidence with as runtime data (report data, challege)
    async fn primary_evidence(&self, runtime_data: Vec<u8>) -> Result<TeeEvidence> {
        let req = GetEvidenceRequest {
            RuntimeData: runtime_data,
            ..Default::default()
        };
        let res = self
            .client
            .get_evidence(
                context::with_timeout(AA_TTRPC_TIMEOUT_SECONDS * 1000 * 1000 * 1000),
                &req,
            )
            .await
            .map_err(|e| Error::AAEvidenceProvider(format!("call ttrpc failed: {e}")))?;
        let evidence = serde_json::from_slice(&res.Evidence)
            .map_err(|e| Error::AAEvidenceProvider(format!("illegal evidence format: {e}")))?;
        Ok(evidence)
    }

    /// Get additional evidence with runtime data (report data, challege)
    async fn get_additional_evidence(&self, runtime_data: Vec<u8>) -> Result<String> {
        let req = GetAdditionalEvidenceRequest {
            RuntimeData: runtime_data,
            ..Default::default()
        };
        let res = self
            .client
            .get_additional_evidence(
                context::with_timeout(AA_TTRPC_TIMEOUT_SECONDS * 1000 * 1000 * 1000),
                &req,
            )
            .await
            .map_err(|e| Error::AAEvidenceProvider(format!("call ttrpc failed: {e}")))?;

        let evidence = String::from_utf8(res.Evidence)
            .map_err(|e| Error::AAEvidenceProvider(format!("failed to parse evidence: {e}")))?;

        Ok(evidence)
    }

    /// Get the underlying Tee type
    async fn get_tee_type(&self) -> Result<Tee> {
        let req = GetTeeTypeRequest {
            ..Default::default()
        };
        let res = self
            .client
            .get_tee_type(
                context::with_timeout(AA_TTRPC_TIMEOUT_SECONDS * 1000 * 1000 * 1000),
                &req,
            )
            .await
            .map_err(|e| Error::AAEvidenceProvider(format!("call ttrpc failed: {e}")))?;

        let tee = serde_json::from_value(json!(res.tee))
            .map_err(|e| Error::AAEvidenceProvider(format!("failed to parse Tee type: {e}")))?;
        Ok(tee)
    }

    async fn get_tee_metadata(&self) -> Result<TotalTeeInfo> {
        let req = GetTeeMetadataRequest {
            ..Default::default()
        };
        let res = self
            .client
            .get_tee_metadata(
                context::with_timeout(AA_TTRPC_TIMEOUT_SECONDS * 1000 * 1000 * 1000),
                &req,
            )
            .await
            .map_err(|e| Error::AAEvidenceProvider(format!("call ttrpc failed: {e}")))?;
        let Some(primary_tee) = res.primary_tee.into_option() else {
            return Err(Error::AAEvidenceProvider(
                "primary tee is not found".to_string(),
            ));
        };

        let res = TotalTeeInfo {
            primary_tee: TeeInfo {
                tee: primary_tee
                    .tee
                    .parse()
                    .map_err(|e| Error::AAEvidenceProvider(format!("failed to parse tee: {e}")))?,
                metadata: primary_tee
                    .metadata
                    .map(|metadata| serde_json::from_str(&metadata))
                    .transpose()
                    .map_err(|e| {
                        Error::AAEvidenceProvider(format!("failed to parse metadata: {e}"))
                    })?,
            },
            additional_tees: res
                .additional_tees
                .into_iter()
                .map(|tee| {
                    Ok(TeeInfo {
                        tee: tee.tee.parse().map_err(|e| {
                            Error::AAEvidenceProvider(format!("failed to parse tee: {e}"))
                        })?,
                        metadata: tee
                            .metadata
                            .map(|metadata| serde_json::from_str(&metadata))
                            .transpose()
                            .map_err(|e| {
                                Error::AAEvidenceProvider(format!("failed to parse metadata: {e}"))
                            })?,
                    })
                })
                .collect::<Result<Vec<TeeInfo>>>()?,
        };

        Ok(res)
    }
}
