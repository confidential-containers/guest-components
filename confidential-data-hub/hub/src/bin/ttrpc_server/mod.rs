// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{error::Error as _, sync::Arc};

use anyhow::Result;
use async_trait::async_trait;
use confidential_data_hub::{hub::Hub, CdhConfig, DataHub};
use lazy_static::lazy_static;
use log::{debug, error};
use storage::volume_type::Storage;
use tokio::sync::RwLock;
use ttrpc::{asynchronous::TtrpcContext, Code, Error, Status};

use crate::{
    format_error,
    message::{KeyProviderInput, KeyUnwrapOutput, KeyUnwrapResults},
    protos::{
        api::{
            GetResourceRequest, GetResourceResponse, ImagePullRequest, ImagePullResponse,
            SecureMountRequest, SecureMountResponse, UnsealSecretInput, UnsealSecretOutput,
        },
        api_ttrpc::{
            GetResourceService, ImagePullService, SealedSecretService, SecureMountService,
        },
        keyprovider::{KeyProviderKeyWrapProtocolInput, KeyProviderKeyWrapProtocolOutput},
        keyprovider_ttrpc::KeyProviderService,
    },
};

lazy_static! {
    static ref HUB: Arc<RwLock<Option<Hub>>> = Arc::new(RwLock::new(None));
}

pub struct Server;

impl Server {
    async fn init(config: &CdhConfig) -> Result<()> {
        let mut writer = HUB.write().await;
        if writer.is_none() {
            let hub = Hub::new(config.clone()).await?;
            *writer = Some(hub);
        }

        Ok(())
    }

    pub async fn new(config: &CdhConfig) -> Result<Self> {
        Self::init(config).await?;
        Ok(Self)
    }
}

#[async_trait]
impl SealedSecretService for Server {
    async fn unseal_secret(
        &self,
        _ctx: &TtrpcContext,
        input: UnsealSecretInput,
    ) -> ::ttrpc::Result<UnsealSecretOutput> {
        debug!("[ttRPC CDH] get new UnsealSecret request");
        let reader = HUB.read().await;
        let reader = reader.as_ref().expect("must be initialized");
        let plaintext = reader.unseal_secret(input.secret).await.map_err(|e| {
            let detailed_error = format_error!(e);
            error!("[ttRPC CDH] UnsealSecret :\n{detailed_error}");
            let mut status = Status::new();
            status.set_code(Code::INTERNAL);
            status.set_message("[CDH] [ERROR]: Unseal Secret failed".into());
            Error::RpcStatus(status)
        })?;

        let mut reply = UnsealSecretOutput::new();
        reply.plaintext = plaintext;
        debug!("[ttRPC CDH] send back plaintext of the sealed secret");
        Ok(reply)
    }
}

#[async_trait]
impl GetResourceService for Server {
    async fn get_resource(
        &self,
        _ctx: &TtrpcContext,
        req: GetResourceRequest,
    ) -> ::ttrpc::Result<GetResourceResponse> {
        debug!("[ttRPC CDH] get new GetResource request");
        let reader = HUB.read().await;
        let reader = reader.as_ref().expect("must be initialized");
        let resource = reader.get_resource(req.ResourcePath).await.map_err(|e| {
            let detailed_error = format_error!(e);
            error!("[ttRPC CDH] GetResource :\n{detailed_error}");
            let mut status = Status::new();
            status.set_code(Code::INTERNAL);
            status.set_message("[CDH] [ERROR]: Get Resource failed".into());
            Error::RpcStatus(status)
        })?;

        let mut reply = GetResourceResponse::new();
        reply.Resource = resource;
        debug!("[ttRPC CDH] send back the resource");
        Ok(reply)
    }
}

#[async_trait]
impl KeyProviderService for Server {
    async fn un_wrap_key(
        &self,
        _ctx: &TtrpcContext,
        req: KeyProviderKeyWrapProtocolInput,
    ) -> ::ttrpc::Result<KeyProviderKeyWrapProtocolOutput> {
        debug!("[ttRPC CDH] get new UnWrapKey request");
        let reader = HUB.read().await;
        let reader = reader.as_ref().expect("must be initialized");
        let key_provider_input: KeyProviderInput =
            serde_json::from_slice(&req.KeyProviderKeyWrapProtocolInput[..]).map_err(|e| {
                error!("[ttRPC CDH] UnwrapKey parse KeyProviderInput failed : {e}");
                let mut status = Status::new();
                status.set_code(Code::INTERNAL);
                status.set_message("[ERROR] UnwrapKey Parse request failed".into());
                Error::RpcStatus(status)
            })?;

        let annotation_packet = key_provider_input.get_annotation().map_err(|e| {
            error!("[ttRPC CDH] UnwrapKey get AnnotationPacket failed: {e}");
            let mut status = Status::new();
            status.set_code(Code::INTERNAL);
            status.set_message("[ERROR] UnwrapKey Parse request failed".to_string());
            Error::RpcStatus(status)
        })?;

        debug!("[ttRPC CDH] Call CDH to Unwrap Key...");
        let decrypted_optsdata = reader.unwrap_key(&annotation_packet).await.map_err(|e| {
            let detailed_error = format_error!(e);
            error!("[ttRPC CDH] UnWrapKey :\n{detailed_error}");
            let mut status = Status::new();
            status.set_code(Code::INTERNAL);
            status.set_message("[CDH] [ERROR]: UnwrapKey failed".to_string());
            Error::RpcStatus(status)
        })?;

        let mut reply = KeyProviderKeyWrapProtocolOutput::new();

        // Construct output structure and serialize it as the return value of gRPC
        let output_struct = KeyUnwrapOutput {
            keyunwrapresults: KeyUnwrapResults {
                optsdata: decrypted_optsdata,
            },
        };

        let lek = serde_json::to_vec(&output_struct).map_err(|e| {
            error!("[ttRPC CDH] UnWrapKey failed to serialize LEK : {e}");
            let mut status = Status::new();
            status.set_code(Code::INTERNAL);
            status.set_message("[CDH] [ERROR]: UnwrapKey serialize response failed".to_string());
            Error::RpcStatus(status)
        })?;

        reply.KeyProviderKeyWrapProtocolOutput = lek;
        debug!("[ttRPC CDH] unwrap key succeeded.");
        Ok(reply)
    }
}

#[async_trait]
impl SecureMountService for Server {
    async fn secure_mount(
        &self,
        _ctx: &TtrpcContext,
        req: SecureMountRequest,
    ) -> ::ttrpc::Result<SecureMountResponse> {
        debug!("[ttRPC CDH] get new secure mount request");
        let reader = HUB.read().await;
        let reader = reader.as_ref().expect("must be initialized");
        let storage = Storage {
            volume_type: req.volume_type,
            options: req.options,
            flags: req.flags,
            mount_point: req.mount_point,
        };
        let resource = reader.secure_mount(storage).await.map_err(|e| {
            let detailed_error = format_error!(e);
            error!("[ttRPC CDH] Secure Mount :\n{detailed_error}");
            let mut status = Status::new();
            status.set_code(Code::INTERNAL);
            status.set_message("[CDH] [ERROR]: secure mount failed".to_string());
            Error::RpcStatus(status)
        })?;

        let mut reply = SecureMountResponse::new();
        reply.mount_path = resource;
        debug!("[ttRPC CDH] secure mount succeeded.");
        Ok(reply)
    }
}

#[async_trait]
impl ImagePullService for Server {
    async fn pull_image(
        &self,
        _ctx: &TtrpcContext,
        req: ImagePullRequest,
    ) -> ::ttrpc::Result<ImagePullResponse> {
        debug!("[ttRPC CDH] get new image pull request");
        let reader = HUB.read().await;
        let reader = reader.as_ref().expect("must be initialized");
        let manifest_digest = reader
            .pull_image(&req.image_url, &req.bundle_path)
            .await
            .map_err(|e| {
                let detailed_error = format_error!(e);
                error!("[ttRPC CDH] Pull Image :\n{detailed_error}");
                let mut status = Status::new();
                status.set_code(Code::INTERNAL);
                status.set_message("[CDH] [ERROR]: pull image failed".to_string());
                Error::RpcStatus(status)
            })?;

        let mut reply = ImagePullResponse::new();
        reply.manifest_digest = manifest_digest;
        debug!("[ttRPC CDH] pull image succeeded.");
        Ok(reply)
    }
}
