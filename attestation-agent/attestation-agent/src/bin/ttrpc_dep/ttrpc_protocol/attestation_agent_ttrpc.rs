// This file is generated by ttrpc-compiler 0.6.3. Do not edit
// @generated

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unknown_lints)]
#![allow(clipto_camel_casepy)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]
#![allow(clippy::all)]
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
            client: client,
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

    pub async fn bind_init_data(&self, ctx: ttrpc::context::Context, req: &super::attestation_agent::BindInitDataRequest) -> ::ttrpc::Result<super::attestation_agent::BindInitDataResponse> {
        let mut cres = super::attestation_agent::BindInitDataResponse::new();
        ::ttrpc::async_client_request!(self, ctx, req, "attestation_agent.AttestationAgentService", "BindInitData", cres);
    }

    pub async fn update_configuration(&self, ctx: ttrpc::context::Context, req: &super::attestation_agent::UpdateConfigurationRequest) -> ::ttrpc::Result<super::attestation_agent::UpdateConfigurationResponse> {
        let mut cres = super::attestation_agent::UpdateConfigurationResponse::new();
        ::ttrpc::async_client_request!(self, ctx, req, "attestation_agent.AttestationAgentService", "UpdateConfiguration", cres);
    }

    pub async fn get_tee_type(&self, ctx: ttrpc::context::Context, req: &super::attestation_agent::GetTeeTypeRequest) -> ::ttrpc::Result<super::attestation_agent::GetTeeTypeResponse> {
        let mut cres = super::attestation_agent::GetTeeTypeResponse::new();
        ::ttrpc::async_client_request!(self, ctx, req, "attestation_agent.AttestationAgentService", "GetTeeType", cres);
    }

    pub async fn get_derived_key(&self, ctx: ttrpc::context::Context, req: &super::attestation_agent::GetDerivedKeyRequest) -> ::ttrpc::Result<super::attestation_agent::GetDerivedKeyResponse> {
        let mut cres = super::attestation_agent::GetDerivedKeyResponse::new();
        ::ttrpc::async_client_request!(self, ctx, req, "attestation_agent.AttestationAgentService", "GetDerivedKey", cres);
    }
}

struct GetEvidenceMethod {
    service: Arc<dyn AttestationAgentService + Send + Sync>,
}

#[async_trait]
impl ::ttrpc::r#async::MethodHandler for GetEvidenceMethod {
    async fn handler(&self, ctx: ::ttrpc::r#async::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<::ttrpc::Response> {
        ::ttrpc::async_request_handler!(self, ctx, req, attestation_agent, GetEvidenceRequest, get_evidence);
    }
}

struct GetTokenMethod {
    service: Arc<dyn AttestationAgentService + Send + Sync>,
}

#[async_trait]
impl ::ttrpc::r#async::MethodHandler for GetTokenMethod {
    async fn handler(&self, ctx: ::ttrpc::r#async::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<::ttrpc::Response> {
        ::ttrpc::async_request_handler!(self, ctx, req, attestation_agent, GetTokenRequest, get_token);
    }
}

struct ExtendRuntimeMeasurementMethod {
    service: Arc<dyn AttestationAgentService + Send + Sync>,
}

#[async_trait]
impl ::ttrpc::r#async::MethodHandler for ExtendRuntimeMeasurementMethod {
    async fn handler(&self, ctx: ::ttrpc::r#async::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<::ttrpc::Response> {
        ::ttrpc::async_request_handler!(self, ctx, req, attestation_agent, ExtendRuntimeMeasurementRequest, extend_runtime_measurement);
    }
}

struct BindInitDataMethod {
    service: Arc<dyn AttestationAgentService + Send + Sync>,
}

#[async_trait]
impl ::ttrpc::r#async::MethodHandler for BindInitDataMethod {
    async fn handler(&self, ctx: ::ttrpc::r#async::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<::ttrpc::Response> {
        ::ttrpc::async_request_handler!(self, ctx, req, attestation_agent, BindInitDataRequest, bind_init_data);
    }
}

struct UpdateConfigurationMethod {
    service: Arc<dyn AttestationAgentService + Send + Sync>,
}

#[async_trait]
impl ::ttrpc::r#async::MethodHandler for UpdateConfigurationMethod {
    async fn handler(&self, ctx: ::ttrpc::r#async::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<::ttrpc::Response> {
        ::ttrpc::async_request_handler!(self, ctx, req, attestation_agent, UpdateConfigurationRequest, update_configuration);
    }
}

struct GetTeeTypeMethod {
    service: Arc<dyn AttestationAgentService + Send + Sync>,
}

#[async_trait]
impl ::ttrpc::r#async::MethodHandler for GetTeeTypeMethod {
    async fn handler(&self, ctx: ::ttrpc::r#async::TtrpcContext, req: ::ttrpc::Request) -> ::ttrpc::Result<::ttrpc::Response> {
        ::ttrpc::async_request_handler!(self, ctx, req, attestation_agent, GetTeeTypeRequest, get_tee_type);
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
    async fn bind_init_data(&self, _ctx: &::ttrpc::r#async::TtrpcContext, _: super::attestation_agent::BindInitDataRequest) -> ::ttrpc::Result<super::attestation_agent::BindInitDataResponse> {
        Err(::ttrpc::Error::RpcStatus(::ttrpc::get_status(::ttrpc::Code::NOT_FOUND, "/attestation_agent.AttestationAgentService/BindInitData is not supported".to_string())))
    }
    async fn update_configuration(&self, _ctx: &::ttrpc::r#async::TtrpcContext, _: super::attestation_agent::UpdateConfigurationRequest) -> ::ttrpc::Result<super::attestation_agent::UpdateConfigurationResponse> {
        Err(::ttrpc::Error::RpcStatus(::ttrpc::get_status(::ttrpc::Code::NOT_FOUND, "/attestation_agent.AttestationAgentService/UpdateConfiguration is not supported".to_string())))
    }
    async fn get_tee_type(&self, _ctx: &::ttrpc::r#async::TtrpcContext, _: super::attestation_agent::GetTeeTypeRequest) -> ::ttrpc::Result<super::attestation_agent::GetTeeTypeResponse> {
        Err(::ttrpc::Error::RpcStatus(::ttrpc::get_status(::ttrpc::Code::NOT_FOUND, "/attestation_agent.AttestationAgentService/GetTeeType is not supported".to_string())))
    }
}

pub fn create_attestation_agent_service(service: Arc<dyn AttestationAgentService + Send + Sync>) -> HashMap<String, ::ttrpc::r#async::Service> {
    let mut ret = HashMap::new();
    let mut methods = HashMap::new();
    let streams = HashMap::new();

    methods.insert("GetEvidence".to_string(),
                    Box::new(GetEvidenceMethod{service: service.clone()}) as Box<dyn ::ttrpc::r#async::MethodHandler + Send + Sync>);

    methods.insert("GetToken".to_string(),
                    Box::new(GetTokenMethod{service: service.clone()}) as Box<dyn ::ttrpc::r#async::MethodHandler + Send + Sync>);

    methods.insert("ExtendRuntimeMeasurement".to_string(),
                    Box::new(ExtendRuntimeMeasurementMethod{service: service.clone()}) as Box<dyn ::ttrpc::r#async::MethodHandler + Send + Sync>);

    methods.insert("BindInitData".to_string(),
                    Box::new(BindInitDataMethod{service: service.clone()}) as Box<dyn ::ttrpc::r#async::MethodHandler + Send + Sync>);

    methods.insert("UpdateConfiguration".to_string(),
                    Box::new(UpdateConfigurationMethod{service: service.clone()}) as Box<dyn ::ttrpc::r#async::MethodHandler + Send + Sync>);

    methods.insert("GetTeeType".to_string(),
                    Box::new(GetTeeTypeMethod{service: service.clone()}) as Box<dyn ::ttrpc::r#async::MethodHandler + Send + Sync>);

    ret.insert("attestation_agent.AttestationAgentService".to_string(), ::ttrpc::r#async::Service{ methods, streams });
    ret
}
