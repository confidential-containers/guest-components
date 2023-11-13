// This file is generated by ttrpc-compiler 0.6.1. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clipto_camel_casepy)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]
use protobuf::{CodedInputStream, CodedOutputStream, Message};
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;

#[derive(Clone)]
pub struct AttestationAgentServiceClient {
    client: ::ttrpc::r#async::Client,
}

impl AttestationAgentServiceClient {
    pub fn new(client: ::ttrpc::r#async::Client) -> Self {
        AttestationAgentServiceClient {
            client,
        }
    }

    pub async fn get_evidence(&self, ctx: ttrpc::context::Context, req: &super::attestation_agent::GetEvidenceRequest) -> ::ttrpc::Result<super::attestation_agent::GetEvidenceResponse> {
        let mut cres = super::attestation_agent::GetEvidenceResponse::new();
        ::ttrpc::async_client_request!(self, ctx, req, "attestation_agent.AttestationAgentService", "GetEvidence", cres);
    }

    pub async fn get_token(&self, ctx: ttrpc::context::Context, req: &super::attestation_agent::GetTokenRequest) -> ::ttrpc::Result<super::attestation_agent::GetTokenResponse> {
        let mut cres = super::attestation_agent::GetTokenResponse::new();
        ::ttrpc::async_client_request!(self, ctx, req, "attestation_agent.AttestationAgentService", "GetToken", cres);
    }

    pub async fn extend_runtime_measurement(&self, ctx: ttrpc::context::Context, req: &super::attestation_agent::ExtendRuntimeMeasurementRequest) -> ::ttrpc::Result<super::attestation_agent::ExtendRuntimeMeasurementResponse> {
        let mut cres = super::attestation_agent::ExtendRuntimeMeasurementResponse::new();
        ::ttrpc::async_client_request!(self, ctx, req, "attestation_agent.AttestationAgentService", "ExtendRuntimeMeasurement", cres);
    }
}

struct GetEvidenceMethod {
    service: Arc<Box<dyn AttestationAgentService + Send + Sync>>,
}

#[async_trait]
impl ::ttrpc::r#async::MethodHandler for GetEvidenceMethod {
    async fn handler(&self, ctx: ::ttrpc::r#async::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<::ttrpc::Response> {
        ::ttrpc::async_request_handler!(self, ctx, req, attestation_agent, GetEvidenceRequest, get_evidence);
    }
}

struct GetTokenMethod {
    service: Arc<Box<dyn AttestationAgentService + Send + Sync>>,
}

#[async_trait]
impl ::ttrpc::r#async::MethodHandler for GetTokenMethod {
    async fn handler(&self, ctx: ::ttrpc::r#async::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<::ttrpc::Response> {
        ::ttrpc::async_request_handler!(self, ctx, req, attestation_agent, GetTokenRequest, get_token);
    }
}

struct ExtendRuntimeMeasurementMethod {
    service: Arc<Box<dyn AttestationAgentService + Send + Sync>>,
}

#[async_trait]
impl ::ttrpc::r#async::MethodHandler for ExtendRuntimeMeasurementMethod {
    async fn handler(&self, ctx: ::ttrpc::r#async::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<::ttrpc::Response> {
        ::ttrpc::async_request_handler!(self, ctx, req, attestation_agent, ExtendRuntimeMeasurementRequest, extend_runtime_measurement);
    }
}

#[async_trait]
pub trait AttestationAgentService: Sync {
    async fn get_evidence(&self, _ctx: &::ttrpc::r#async::TtrpcContext, _: super::attestation_agent::GetEvidenceRequest) -> ::ttrpc::Result<super::attestation_agent::GetEvidenceResponse> {
        Err(::ttrpc::Error::RpcStatus(::ttrpc::get_status(::ttrpc::Code::NOT_FOUND, "/attestation_agent.AttestationAgentService/GetEvidence is not supported".to_string())))
    }
    async fn get_token(&self, _ctx: &::ttrpc::r#async::TtrpcContext, _: super::attestation_agent::GetTokenRequest) -> ::ttrpc::Result<super::attestation_agent::GetTokenResponse> {
        Err(::ttrpc::Error::RpcStatus(::ttrpc::get_status(::ttrpc::Code::NOT_FOUND, "/attestation_agent.AttestationAgentService/GetToken is not supported".to_string())))
    }
    async fn extend_runtime_measurement(&self, _ctx: &::ttrpc::r#async::TtrpcContext, _: super::attestation_agent::ExtendRuntimeMeasurementRequest) -> ::ttrpc::Result<super::attestation_agent::ExtendRuntimeMeasurementResponse> {
        Err(::ttrpc::Error::RpcStatus(::ttrpc::get_status(::ttrpc::Code::NOT_FOUND, "/attestation_agent.AttestationAgentService/ExtendRuntimeMeasurement is not supported".to_string())))
    }
}

pub fn create_attestation_agent_service(service: Arc<Box<dyn AttestationAgentService + Send + Sync>>) -> HashMap<String, ::ttrpc::r#async::Service> {
    let mut ret = HashMap::new();
    let mut methods = HashMap::new();
    let streams = HashMap::new();

    methods.insert("GetEvidence".to_string(),
                    Box::new(GetEvidenceMethod{service: service.clone()}) as Box<dyn ::ttrpc::r#async::MethodHandler + Send + Sync>);

    methods.insert("GetToken".to_string(),
                    Box::new(GetTokenMethod{service: service.clone()}) as Box<dyn ::ttrpc::r#async::MethodHandler + Send + Sync>);

    methods.insert("ExtendRuntimeMeasurement".to_string(),
                    Box::new(ExtendRuntimeMeasurementMethod{service: service.clone()}) as Box<dyn ::ttrpc::r#async::MethodHandler + Send + Sync>);

    ret.insert("attestation_agent.AttestationAgentService".to_string(), ::ttrpc::r#async::Service{ methods, streams });
    ret
}
