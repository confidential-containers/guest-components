// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;

use confidential_data_hub::{hub::Hub, DataHub};
use log::{debug, error};
use std::{error::Error as _, net::SocketAddr, sync::Arc};
use storage::volume_type::Storage;
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};

use crate::{
    format_error,
    message::{KeyProviderInput, KeyUnwrapOutput, KeyUnwrapResults},
};
use api::{
    get_resource_service_server::{GetResourceService, GetResourceServiceServer},
    key_provider_service_server::{KeyProviderService, KeyProviderServiceServer},
    sealed_secret_service_server::{SealedSecretService, SealedSecretServiceServer},
    secure_mount_service_server::{SecureMountService, SecureMountServiceServer},
    GetResourceRequest, GetResourceResponse, KeyProviderKeyWrapProtocolInput,
    KeyProviderKeyWrapProtocolOutput, SecureMountRequest, SecureMountResponse, UnsealSecretInput,
    UnsealSecretOutput,
};

mod api {
    tonic::include_proto!("api");
    tonic::include_proto!("keyprovider");
}

pub struct Cdh {
    inner: RwLock<Hub>,
}

#[tonic::async_trait]
impl SealedSecretService for Arc<Cdh> {
    async fn unseal_secret(
        &self,
        request: Request<UnsealSecretInput>,
    ) -> Result<Response<UnsealSecretOutput>, Status> {
        debug!("[gRPC CDH] get new UnsealSecret request");
        let request = request.into_inner();

        let cdh = self.inner.read().await;

        let plaintext = cdh.unseal_secret(request.secret).await.map_err(|e| {
            let detailed_error = format_error!(e);
            error!("[gRPC CDH] Call CDH to unseal secret failed:\n{detailed_error}");
            Status::internal(format!("[ERROR] CDH unseal secret failed: {}", e))
        })?;

        debug!("[gRPC CDH] Unseal secret successfully!");

        let reply = UnsealSecretOutput { plaintext };

        Result::Ok(Response::new(reply))
    }
}

#[tonic::async_trait]
impl GetResourceService for Arc<Cdh> {
    async fn get_resource(
        &self,
        request: Request<GetResourceRequest>,
    ) -> Result<Response<GetResourceResponse>, Status> {
        debug!("[gRPC CDH] get new GetResource request");
        let request = request.into_inner();

        let cdh = self.inner.read().await;

        let resource = cdh.get_resource(request.resource_path).await.map_err(|e| {
            let detailed_error = format_error!(e);
            error!("[gRPC CDH] Call CDH to get resource failed:\n{detailed_error}");
            Status::internal(format!("[ERROR] CDH get resource failed: {}", e))
        })?;

        debug!("[gRPC CDH] Get resource successfully!");

        let reply = GetResourceResponse { resource };

        Result::Ok(Response::new(reply))
    }
}

#[tonic::async_trait]
impl SecureMountService for Arc<Cdh> {
    async fn secure_mount(
        &self,
        request: Request<SecureMountRequest>,
    ) -> Result<Response<SecureMountResponse>, Status> {
        debug!("[gRPC CDH] get new SecureMount request");
        let request = request.into_inner();

        let cdh = self.inner.read().await;
        let storage = Storage {
            volume_type: request.volume_type,
            options: request.options,
            flags: request.flags,
            mount_point: request.mount_point,
        };
        let mount_path = cdh.secure_mount(storage).await.map_err(|e| {
            let detailed_error = format_error!(e);
            error!("[gRPC CDH] Call CDH to secure mount failed:\n{detailed_error}");
            Status::internal(format!("[ERROR] CDH secure mount failed: {}", e))
        })?;

        debug!("[gRPC CDH] Secure mount successfully!");

        let reply = SecureMountResponse { mount_path };

        Result::Ok(Response::new(reply))
    }
}

#[tonic::async_trait]
impl KeyProviderService for Arc<Cdh> {
    async fn wrap_key(
        &self,
        _request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        Err(Status::unimplemented("WrapKey not implemented."))
    }

    async fn un_wrap_key(
        &self,
        request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        debug!("[gRPC CDH] get new UnwrapKey request");
        let request = request.into_inner();

        let cdh = self.inner.read().await;

        let key_provider_input: KeyProviderInput = serde_json::from_slice(
            &request.key_provider_key_wrap_protocol_input[..],
        )
        .map_err(|e| {
            let detailed_error = format_error!(e);
            error!("[gRPC CDH] Call CDH to Unwrap Key failed:\n{detailed_error}");
            Status::internal(format!("[ERROR] CDH Unwrap Key failed: {}", e))
        })?;

        let annotation_packet = key_provider_input.get_annotation().map_err(|e| {
            let detailed_error = format_error!(e);
            error!("[gRPC CDH] Call CDH to Unwrap Key failed:\n{detailed_error}");
            Status::internal(format!("[ERROR] CDH Unwrap Key failed: {}", e))
        })?;

        let decrypted_optsdata = cdh.unwrap_key(&annotation_packet).await.map_err(|e| {
            let detailed_error = format_error!(e);
            error!("[gRPC CDH] Call CDH to Unwrap Key failed:\n{detailed_error}");
            Status::internal(format!("[ERROR] CDH Unwrap Key failed: {}", e))
        })?;

        // Construct output structure and serialize it as the return value of gRPC
        let output_struct = KeyUnwrapOutput {
            keyunwrapresults: KeyUnwrapResults {
                optsdata: decrypted_optsdata,
            },
        };
        let key_provider_key_wrap_protocol_output =
            serde_json::to_vec(&output_struct).map_err(|e| {
                let detailed_error = format_error!(e);
                error!("[gRPC CDH] Call CDH to Unwrap Key failed:\n{detailed_error}");
                Status::internal(format!("[ERROR] CDH Unwrap Key failed: {}", e))
            })?;

        debug!("[gRPC CDH] Unwrap Key successfully!");

        let reply = KeyProviderKeyWrapProtocolOutput {
            key_provider_key_wrap_protocol_output,
        };

        Result::Ok(Response::new(reply))
    }
}

pub async fn start_grpc_service(socket: SocketAddr, cdh: Hub) -> Result<()> {
    let service = Cdh { inner: cdh.into() };
    let service = Arc::new(service);
    Server::builder()
        .add_service(SealedSecretServiceServer::new(service.clone()))
        .add_service(GetResourceServiceServer::new(service.clone()))
        .add_service(SecureMountServiceServer::new(service.clone()))
        .add_service(KeyProviderServiceServer::new(service))
        .serve(socket)
        .await?;
    Ok(())
}
