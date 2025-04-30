// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
use crypto::HashAlgorithm;
use kbs_types::{Tee, TeePubKey};
use serde_json::json;
use ttrpc::context;

use crate::{
    ttrpc_protos::{
        attestation_agent::{GetEvidenceRequest, GetTeeTypeRequest},
        attestation_agent_ttrpc::AttestationAgentServiceClient,
    },
    Error, Result,
};

use super::EvidenceProvider;

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
            .map_err(|e| Error::AATokenProvider(format!("ttrpc connect failed {e}")))?;
        let client = AttestationAgentServiceClient::new(c);
        Ok(Self { client })
    }
}

#[async_trait]
impl EvidenceProvider for AAEvidenceProvider {
    /// Get evidence with as runtime data (report data, challege)
    async fn get_evidence(
        &self,
        tee_pubkey: TeePubKey,
        nonce: String,
        hash_algorithm: HashAlgorithm,
    ) -> Result<String> {
        let pubkey_string = serde_json::to_string(&tee_pubkey).map_err(|e| {
            Error::AAEvidenceProvider(format!("Failed to serialize Tee Pub Key: {e}"))
        })?;
        let req = GetEvidenceRequest {
            TeePubKey: pubkey_string,
            Nonce: nonce,
            HashAlgorithm: hash_algorithm.to_string(),
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
        let evidence = String::from_utf8(res.Evidence)
            .map_err(|e| Error::AAEvidenceProvider(format!("non-utf8 evidence: {e}")))?;
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
}
