// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use confidential_data_hub::{hub::Hub, DataHub};
use lazy_static::lazy_static;
use log::debug;
use storage::volume_type::Storage;
use tokio::sync::RwLock;
use ttrpc::{asynchronous::TtrpcContext, Code, Error, Status};

use crate::{
    api::{
        GetResourceRequest, GetResourceResponse, KeyProviderKeyWrapProtocolInput,
        KeyProviderKeyWrapProtocolOutput, SecureMountRequest, SecureMountResponse,
        UnsealSecretInput, UnsealSecretOutput,
    },
    api_ttrpc::{GetResourceService, KeyProviderService, SealedSecretService, SecureMountService},
    server::message::{KeyProviderInput, KeyUnwrapOutput, KeyUnwrapResults},
};

lazy_static! {
    static ref HUB: Arc<RwLock<Option<Hub>>> = Arc::new(RwLock::new(None));
}

mod message;

pub struct Server;

impl Server {
    async fn init() -> Result<()> {
        let mut writer = HUB.write().await;
        if writer.is_none() {
            let hub = Hub::new().await?;
            *writer = Some(hub);
        }

        Ok(())
    }

    pub async fn new() -> Result<Self> {
        Self::init().await?;
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
        debug!("get new UnsealSecret request");
        let reader = HUB.read().await;
        let reader = reader.as_ref().expect("must be initialized");
        let plaintext = reader.unseal_secret(input.secret).await.map_err(|e| {
            let mut status = Status::new();
            status.set_code(Code::INTERNAL);
            status.set_message(format!("[CDH] [ERROR]: Unseal Secret failed: {e}"));
            Error::RpcStatus(status)
        })?;

        let mut reply = UnsealSecretOutput::new();
        reply.plaintext = plaintext;
        debug!("send back plaintext of the sealed secret");
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
        debug!("get new GetResource request");
        let reader = HUB.read().await;
        let reader = reader.as_ref().expect("must be initialized");
        let resource = reader.get_resource(req.ResourcePath).await.map_err(|e| {
            let mut status = Status::new();
            status.set_code(Code::INTERNAL);
            status.set_message(format!("[CDH] [ERROR]: Get Resource failed: {e}"));
            Error::RpcStatus(status)
        })?;

        let mut reply = GetResourceResponse::new();
        reply.Resource = resource;
        debug!("send back the resource");
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
        debug!("get new UnWrapKey request");
        let reader = HUB.read().await;
        let reader = reader.as_ref().expect("must be initialized");
        let key_provider_input: KeyProviderInput =
            serde_json::from_slice(&req.KeyProviderKeyWrapProtocolInput[..]).map_err(|e| {
                let mut status = Status::new();
                status.set_code(Code::INTERNAL);
                status.set_message(format!("[ERROR] UnwrapKey Parse request failed: {e}"));
                Error::RpcStatus(status)
            })?;

        let annotation_packet = key_provider_input.get_annotation().map_err(|e| {
            let mut status = Status::new();
            status.set_code(Code::INTERNAL);
            status.set_message(format!("[ERROR] UnwrapKey Parse request failed: {e}"));
            Error::RpcStatus(status)
        })?;

        debug!("Call CDH to Unwrap Key...");
        let decrypted_optsdata = reader.unwrap_key(&annotation_packet).await.map_err(|e| {
            let mut status = Status::new();
            status.set_code(Code::INTERNAL);
            status.set_message(format!("[CDH] [ERROR]: UnwrapKey failed: {e}"));
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
            let mut status = Status::new();
            status.set_code(Code::INTERNAL);
            status.set_message(format!(
                "[CDH] [ERROR]: UnwrapKey serialize response failed: {e}"
            ));
            Error::RpcStatus(status)
        })?;

        reply.KeyProviderKeyWrapProtocolOutput = lek;
        debug!("send back the resource");
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
        debug!("get new Secure mount request");
        let reader = HUB.read().await;
        let reader = reader.as_ref().expect("must be initialized");
        let storage = Storage {
            driver: req.driver,
            driver_options: req.driver_options,
            source: req.source,
            fstype: req.fstype,
            options: req.options,
            mount_point: req.mount_point,
        };
        let resource = reader.secure_mount(storage).await.map_err(|e| {
            let mut status = Status::new();
            status.set_code(Code::INTERNAL);
            status.set_message(format!("[CDH] [ERROR]: secure mount failed: {e}"));
            Error::RpcStatus(status)
        })?;

        let mut reply = SecureMountResponse::new();
        reply.mount_path = resource;
        debug!("send back the resource");
        Ok(reply)
    }
}
