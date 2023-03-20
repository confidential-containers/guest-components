// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::enc_mods;
use anyhow::*;
use jwt_simple::prelude::Ed25519KeyPair;
use log::*;
use reqwest::Url;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::fs;
use tonic::{transport::Server, Request, Response, Status};

use key_provider::key_provider_service_server::{KeyProviderService, KeyProviderServiceServer};
use key_provider::{KeyProviderKeyWrapProtocolInput, KeyProviderKeyWrapProtocolOutput};
use protocol::keyprovider_structs::*;

pub mod protocol;
pub mod key_provider {
    #![allow(unknown_lints)]
    #![allow(clippy::derive_partial_eq_without_eq)]
    #![allow(clippy::redundant_async_block)]
    tonic::include_proto!("keyprovider");
}

pub struct KeyProvider {
    auth_private_key: Option<Ed25519KeyPair>,
    kbs: Option<Url>,
}

impl KeyProvider {
    pub fn new(auth_private_key: Option<Ed25519KeyPair>, kbs: Option<String>) -> Result<Self> {
        let kbs = match kbs {
            Some(addr) => addr.parse().ok(),
            None => None,
        };

        Ok(Self {
            auth_private_key,
            kbs,
        })
    }
}

#[tonic::async_trait]
impl KeyProviderService for KeyProvider {
    async fn wrap_key(
        &self,
        request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        let input_string = String::from_utf8(
            request.into_inner().key_provider_key_wrap_protocol_input,
        )
        .map_err(|e| {
            Status::invalid_argument(format!(
                "key_provider_key_wrap_protocol_input is not legal utf8 string: {e}"
            ))
        })?;

        debug!("WrapKey API Request Input: {}", input_string);
        let input: KeyProviderInput = serde_json::from_str::<KeyProviderInput>(&input_string)
            .map_err(|e| {
                Status::invalid_argument(format!("parse key provider input failed: {e}"))
            })?;
        let optsdata = input
            .keywrapparams
            .optsdata
            .ok_or_else(|| Status::invalid_argument("illegal keywrapparams without optsdata"))?;
        let params: Vec<String> = input
            .keywrapparams
            .ec
            .ok_or_else(|| Status::invalid_argument("illegal keywrapparams without ec"))?
            .parameters
            .get("attestation-agent")
            .ok_or_else(|| {
                Status::invalid_argument("illegal encryption provider without attestation-agent")
            })?
            .iter()
            // According to
            // https://github.com/containers/ocicrypt/blob/e4a936881fb7cf4b2b8fe49e81b8232fd4c48e97/config/constructors.go#L112,
            // this Vec will only have one element anyways, but let's decode all elements of it
            // just to be sure.
            .filter_map(|p| {
                base64::decode(p)
                    .ok()
                    .and_then(|st| String::from_utf8(st).ok())
            })
            .collect();

        let annotation: String = enc_mods::enc_optsdata_gen_anno(
            (&self.kbs, &self.auth_private_key),
            &base64::decode(optsdata).map_err(|_| Status::aborted("base64 decode"))?,
            params,
        )
        .await
        .map_err(|e| Status::internal(format!("encrypt failed: {e}")))?;

        let output_struct = KeyWrapOutput {
            keywrapresults: KeyWrapResults {
                annotation: annotation.as_bytes().to_vec(),
            },
        };
        let output = serde_json::to_string(&output_struct)
            .map_err(|e| Status::internal(format!("serde json failed: {e}")))?
            .as_bytes()
            .to_vec();
        debug!(
            "WrapKey API output: {}",
            serde_json::to_string(&output_struct)
                .map_err(|e| Status::internal(format!("serde json failed: {e}")))?
        );
        let reply = KeyProviderKeyWrapProtocolOutput {
            key_provider_key_wrap_protocol_output: output,
        };
        debug!("Reply successfully!");

        Result::Ok(Response::new(reply))
    }

    async fn un_wrap_key(
        &self,
        _request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        debug!("The UnWrapKey API is called...");
        debug!("UnWrapKey API is unimplemented!");
        Err(Status::unimplemented(
            "UnWrapKey API of sample-kbs is unimplemented!",
        ))
    }
}

pub async fn start_service(
    socket: SocketAddr,
    auth_private_key: Option<PathBuf>,
    kbs: Option<String>,
) -> Result<()> {
    let auth_private_key = match auth_private_key {
        Some(key_path) => {
            let pem = fs::read_to_string(key_path)
                .await
                .context("open auth private key")?;

            Some(Ed25519KeyPair::from_pem(&pem)?)
        }
        None => None,
    };

    Server::builder()
        .add_service(KeyProviderServiceServer::new(KeyProvider::new(
            auth_private_key,
            kbs,
        )?))
        .serve(socket)
        .await?;
    Ok(())
}
