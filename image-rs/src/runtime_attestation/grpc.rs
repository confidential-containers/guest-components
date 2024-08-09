// Copyright (c) 2024 Intel
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use async_trait::async_trait;

use tonic::transport::Channel;

use super::Client;

use self::attestation_agent::{
    attestation_agent_service_client::AttestationAgentServiceClient,
    ExtendRuntimeMeasurementRequest,
};

mod attestation_agent {
    #![allow(unknown_lints)]
    #![allow(clippy::derive_partial_eq_without_eq)]
    #![allow(clippy::redundant_async_block)]
    tonic::include_proto!("attestation_agent");
}

pub const AA_ADDR: &str = "http://127.0.0.1:50002";

pub struct Grpc {
    inner: AttestationAgentServiceClient<Channel>,
}

impl Grpc {
    pub async fn new() -> Result<Self> {
        let inner = AttestationAgentServiceClient::connect(AA_ADDR).await?;
        Ok(Self { inner })
    }
}

#[async_trait]
impl Client for Grpc {
    async fn extend_runtime_measurement(
        &mut self,
        domain: &str,
        operation: &str,
        content: &str,
    ) -> Result<()> {
        let req = tonic::Request::new(ExtendRuntimeMeasurementRequest {
            domain: domain.to_string(),
            operation: operation.to_string(),
            content: content.to_string(),
            ..Default::default()
        });

        self.inner.extend_runtime_measurement(req).await?;

        Ok(())
    }
}
