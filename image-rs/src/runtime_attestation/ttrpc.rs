// Copyright (c) 2024 Intel
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use async_trait::async_trait;

use super::ttrpc_proto::attestation_agent::ExtendRuntimeMeasurementRequest;
use super::ttrpc_proto::attestation_agent_ttrpc::AttestationAgentServiceClient;
use super::Client;
use ttrpc::context;

const SOCKET_ADDR: &str =
    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

pub struct Ttrpc {
    client: AttestationAgentServiceClient,
}

impl Ttrpc {
    pub fn new() -> Result<Self> {
        let inner = ttrpc::asynchronous::Client::connect(SOCKET_ADDR)?;
        let client = AttestationAgentServiceClient::new(inner);
        Ok(Self { client })
    }
}

#[async_trait]
impl Client for Ttrpc {
    async fn extend_runtime_measurement(
        &mut self,
        domain: &str,
        operation: &str,
        content: &str,
    ) -> Result<()> {
        let req = ExtendRuntimeMeasurementRequest {
            Domain: domain.to_string(),
            Operation: operation.to_string(),
            Content: content.to_string(),
            ..Default::default()
        };
        self.client
            .extend_runtime_measurement(context::with_timeout(50 * 1000 * 1000 * 1000), &req)
            .await
            .map_err(|e| anyhow!("extend runtime measurement ttrpc error: {:?}", e))?;
        Ok(())
    }
}
