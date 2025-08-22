// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::router::ApiHandler;
use anyhow::*;
use async_trait::async_trait;
use hyper::body::HttpBody;
use hyper::{Body, Method, Request, Response};
use protos::ttrpc::aa::attestation_agent::{
    ExtendRuntimeMeasurementRequest, GetEvidenceRequest, GetTokenRequest,
};
use protos::ttrpc::aa::attestation_agent_ttrpc::AttestationAgentServiceClient;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::TTRPC_TIMEOUT;

/// ROOT path for Confidential Data Hub API
pub const AA_ROOT: &str = "/aa";

/// URL for querying CDH get resource API
const AA_TOKEN_URL: &str = "/token";
const AA_EVIDENCE_URL: &str = "/evidence";
const AA_AAEL_URL: &str = "/aael";

pub struct AAClient {
    client: AttestationAgentServiceClient,
    accepted_method: Vec<Method>,
}

#[derive(Deserialize)]
pub struct AaelEvent {
    pub domain: String,
    pub operation: String,
    pub content: String,
}

#[async_trait]
impl ApiHandler for AAClient {
    async fn handle_request(
        &self,
        remote_addr: SocketAddr,
        url_path: &str,
        req: Request<Body>,
    ) -> Result<Response<Body>> {
        if !remote_addr.ip().is_loopback() {
            // Return 403 Forbidden response.
            return self.forbidden();
        }

        if !self.accepted_method.iter().any(|i| i.eq(&req.method())) {
            // Return 405 Method Not Allowed response.
            return self.not_allowed();
        }

        let params: HashMap<String, String> = req
            .uri()
            .query()
            .map(|v| form_urlencoded::parse(v.as_bytes()).into_owned().collect())
            .unwrap_or_default();

        let method = req.method();
        match (url_path, method) {
            (AA_TOKEN_URL, &Method::GET) => match params.get("token_type") {
                Some(token_type) => match self.get_token(token_type).await {
                    std::result::Result::Ok(results) => return self.octet_stream_response(results),
                    Err(e) => return self.internal_error(e.to_string()),
                },
                None => return self.bad_request(),
            },
            (AA_EVIDENCE_URL, &Method::GET) => match params.get("runtime_data") {
                Some(runtime_data) => {
                    match self.get_evidence(&runtime_data.clone().into_bytes()).await {
                        std::result::Result::Ok(results) => {
                            return self.octet_stream_response(results)
                        }
                        Err(e) => return self.internal_error(e.to_string()),
                    }
                }
                None => return self.bad_request(),
            },
            (AA_AAEL_URL, &Method::POST) => {
                let aael_entry: AaelEvent = match req
                    .into_body()
                    .collect()
                    .await
                    .map_err(Error::from)
                    .and_then(|data| {
                        serde_json::from_slice(data.to_bytes().as_ref())
                            .map_err(|e| anyhow!("Illegal AAEL eventry format: {e}"))
                    }) {
                    std::result::Result::Ok(aael_entry) => aael_entry,
                    Err(e) => return self.internal_error(e.to_string()),
                };
                match self
                    .extend_aael_entry(
                        &aael_entry.domain,
                        &aael_entry.operation,
                        &aael_entry.content,
                    )
                    .await
                {
                    std::result::Result::Ok(_) => return self.empty_response(),
                    Err(e) => return self.internal_error(e.to_string()),
                }
            }

            _ => {
                return self.not_found();
            }
        }
    }
}

impl AAClient {
    pub async fn new(aa_addr: &str, accepted_method: Vec<Method>) -> Result<Self> {
        let inner = ttrpc::asynchronous::Client::connect(aa_addr)
            .await
            .context(format!("ttrpc connect to AA addr: {aa_addr} failed!"))?;
        let client = AttestationAgentServiceClient::new(inner);

        Ok(Self {
            client,
            accepted_method,
        })
    }

    pub async fn get_token(&self, token_type: &str) -> Result<Vec<u8>> {
        let req = GetTokenRequest {
            TokenType: token_type.to_string(),
            ..Default::default()
        };
        let res = self
            .client
            .get_token(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.Token)
    }

    pub async fn get_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        let req = GetEvidenceRequest {
            RuntimeData: runtime_data.to_vec(),
            ..Default::default()
        };
        let res = self
            .client
            .get_evidence(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(res.Evidence)
    }

    pub async fn extend_aael_entry(
        &self,
        domain: &str,
        operation: &str,
        content: &str,
    ) -> Result<()> {
        let req = ExtendRuntimeMeasurementRequest {
            Domain: domain.into(),
            Operation: operation.into(),
            Content: content.into(),
            ..Default::default()
        };
        let _ = self
            .client
            .extend_runtime_measurement(ttrpc::context::with_timeout(TTRPC_TIMEOUT), &req)
            .await?;
        Ok(())
    }
}
