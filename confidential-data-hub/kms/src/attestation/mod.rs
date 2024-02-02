// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

mod aa_ttrpc;

use crate::{Error, Result};
use ttrpc::context;

const AA_SOCKET_FILE: &str =
    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

use aa_ttrpc::{
    attestation_agent::GetTokenRequest, attestation_agent_ttrpc::AttestationAgentServiceClient,
};

pub struct AAClient {
    client: AttestationAgentServiceClient,
}

impl AAClient {
    pub async fn new() -> Result<Self> {
        let c = ttrpc::r#async::Client::connect(AA_SOCKET_FILE)
            .map_err(|e| Error::AAClientError(format!("ttrpc connect failed {e}")))?;
        let client = AttestationAgentServiceClient::new(c);
        Ok(Self { client })
    }
}

impl AAClient {
    pub async fn get_token(
        &self,
        token_type: &str,
        structured_runtime_data: &str,
    ) -> Result<Vec<u8>> {
        let req = GetTokenRequest {
            TokenType: token_type.to_string(),
            StructuredRuntimeData: structured_runtime_data.to_string()..Default::default(),
        };
        let bytes = self
            .client
            .get_token(context::with_timeout(50 * 1000 * 1000 * 1000), &req)
            .await
            .map_err(|e| Error::AAClientError(format!("cal ttrpc failed: {e}")))?;
        Ok(bytes.Token)
    }
}
