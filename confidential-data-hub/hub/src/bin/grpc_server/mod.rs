// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;

use confidential_data_hub::{
    storage::volume_type::Storage,
    {hub::Hub, DataHub},
};
use log::{debug, error};
use std::{error::Error as _, net::SocketAddr, sync::Arc};
use tonic::{transport::Server, Request, Response, Status};

use crate::{
    format_error,
    message::{KeyProviderInput, KeyUnwrapOutput, KeyUnwrapResults},
};
use protos::grpc::cdh::{
    api::{
        get_resource_service_server::{GetResourceService, GetResourceServiceServer},
        image_pull_service_server::{ImagePullService, ImagePullServiceServer},
        sealed_secret_service_server::{SealedSecretService, SealedSecretServiceServer},
        secure_mount_service_server::{SecureMountService, SecureMountServiceServer},
        GetResourceRequest, GetResourceResponse, ImagePullRequest, ImagePullResponse,
        SecureMountRequest, SecureMountResponse, UnsealSecretInput, UnsealSecretOutput,
    },
    keyprovider::{
        key_provider_service_server::{KeyProviderService, KeyProviderServiceServer},
        KeyProviderKeyWrapProtocolInput, KeyProviderKeyWrapProtocolOutput,
    },
};

#[derive(Clone)]
pub struct Cdh {
    inner: Arc<Hub>,
}

#[tonic::async_trait]
impl SealedSecretService for Cdh {
    async fn unseal_secret(
        &self,
        request: Request<UnsealSecretInput>,
    ) -> Result<Response<UnsealSecretOutput>, Status> {
        debug!("[gRPC CDH] get new UnsealSecret request");
        let request = request.into_inner();

        let plaintext = self
            .inner
            .unseal_secret(request.secret)
            .await
            .map_err(|e| {
                let detailed_error = format_error!(e);
                error!("[gRPC CDH] Call CDH to unseal secret failed:\n{detailed_error}");
                Status::internal(format!("[CDH] [ERROR]: {e}"))
            })?;

        debug!("[gRPC CDH] Unseal secret successfully!");

        let reply = UnsealSecretOutput { plaintext };

        Result::Ok(Response::new(reply))
    }
}

#[tonic::async_trait]
impl GetResourceService for Cdh {
    async fn get_resource(
        &self,
        request: Request<GetResourceRequest>,
    ) -> Result<Response<GetResourceResponse>, Status> {
        debug!("[gRPC CDH] get new GetResource request");
        let request = request.into_inner();

        let resource = self
            .inner
            .get_resource(request.resource_path)
            .await
            .map_err(|e| {
                let detailed_error = format_error!(e);
                error!("[gRPC CDH] Call CDH to get resource failed:\n{detailed_error}");
                Status::internal(format!("[CDH] [ERROR]: {e}"))
            })?;

        debug!("[gRPC CDH] Get resource successfully!");

        let reply = GetResourceResponse { resource };

        Result::Ok(Response::new(reply))
    }
}

#[tonic::async_trait]
impl SecureMountService for Cdh {
    async fn secure_mount(
        &self,
        request: Request<SecureMountRequest>,
    ) -> Result<Response<SecureMountResponse>, Status> {
        debug!("[gRPC CDH] get new SecureMount request");
        let request = request.into_inner();

        let storage = Storage {
            volume_type: request.volume_type,
            options: request.options,
            flags: request.flags,
            mount_point: request.mount_point,
        };
        let _ = self.inner.secure_mount(storage).await.map_err(|e| {
            let detailed_error = format_error!(e);
            error!("[gRPC CDH] Call CDH to secure mount failed:\n{detailed_error}");
            Status::internal(format!("[CDH] [ERROR]: {e}"))
        })?;

        debug!("[gRPC CDH] Secure mount successfully!");

        let reply = SecureMountResponse {};

        Result::Ok(Response::new(reply))
    }
}

#[tonic::async_trait]
impl ImagePullService for Cdh {
    async fn pull_image(
        &self,
        request: Request<ImagePullRequest>,
    ) -> Result<Response<ImagePullResponse>, Status> {
        debug!("[gRPC CDH] get new ImagePull request");
        let request = request.into_inner();

        let manifest_digest = self
            .inner
            .pull_image(&request.image_url, &request.bundle_path)
            .await
            .map_err(|e| {
                let detailed_error = format_error!(e);
                error!("[gRPC CDH] Call CDH to pull image failed:\n{detailed_error}");
                Status::internal(format!("[CDH] [ERROR]: {e}"))
            })?;

        debug!("[gRPC CDH] Pull image successfully!");

        let reply = ImagePullResponse { manifest_digest };

        Result::Ok(Response::new(reply))
    }
}

#[tonic::async_trait]
impl KeyProviderService for Cdh {
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

        let key_provider_input: KeyProviderInput = serde_json::from_slice(
            &request.key_provider_key_wrap_protocol_input[..],
        )
        .map_err(|e| {
            let detailed_error = format_error!(e);
            error!("[gRPC CDH] Call CDH to Unwrap Key failed:\n{detailed_error}");
            Status::internal(format!("[ERROR] CDH Unwrap Key failed: {e}"))
        })?;

        let annotation_packet = key_provider_input.get_annotation().map_err(|e| {
            let detailed_error = format_error!(e);
            error!("[gRPC CDH] Call CDH to Unwrap Key failed:\n{detailed_error}");
            Status::internal(format!("[ERROR] CDH Unwrap Key failed: {e}"))
        })?;

        let decrypted_optsdata = self
            .inner
            .unwrap_key(&annotation_packet)
            .await
            .map_err(|e| {
                let detailed_error = format_error!(e);
                error!("[gRPC CDH] Call CDH to Unwrap Key failed:\n{detailed_error}");
                Status::internal(format!("[CDH] [ERROR]: {e}"))
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
                Status::internal(format!("[ERROR] CDH Unwrap Key failed: {e}"))
            })?;

        debug!("[gRPC CDH] Unwrap Key successfully!");

        let reply = KeyProviderKeyWrapProtocolOutput {
            key_provider_key_wrap_protocol_output,
        };

        Result::Ok(Response::new(reply))
    }
}

pub async fn start_grpc_service(socket: SocketAddr, inner: Hub) -> Result<()> {
    let service = Cdh {
        inner: Arc::new(inner),
    };
    Server::builder()
        .add_service(SealedSecretServiceServer::new(service.clone()))
        .add_service(GetResourceServiceServer::new(service.clone()))
        .add_service(SecureMountServiceServer::new(service.clone()))
        .add_service(ImagePullServiceServer::new(service.clone()))
        .add_service(KeyProviderServiceServer::new(service))
        .serve(socket)
        .await?;
    Ok(())
}
