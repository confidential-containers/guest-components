// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use base64::Engine;
use log::*;
use std::env;
use tonic::{transport::Server, Request, Response, Status};

use key_provider::key_provider_service_server::{KeyProviderService, KeyProviderServiceServer};
use key_provider::{KeyProviderKeyWrapProtocolInput, KeyProviderKeyWrapProtocolOutput};
use protocol::keyprovider_structs::*;

use crate::config::CoCoKeyproviderConfig;
use crate::encrypt::enc_optsdata_gen_anno;

pub mod protocol;
pub mod key_provider {
    #![allow(unknown_lints)]
    #![allow(clippy::derive_partial_eq_without_eq)]
    #![allow(clippy::redundant_async_block)]
    tonic::include_proto!("keyprovider");
}

pub struct KeyProvider;

impl KeyProvider {
    pub fn new() -> Result<Self> {
        Ok(Self)
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

        let engine = base64::engine::general_purpose::STANDARD;
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
                engine
                    .decode(p)
                    .ok()
                    .and_then(|st| String::from_utf8(st).ok())
            })
            .collect();

        let annotation: String = enc_optsdata_gen_anno(
            &engine
                .decode(optsdata)
                .map_err(|_| Status::aborted("base64 decode"))?,
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

pub async fn start_service(config: CoCoKeyproviderConfig) -> Result<()> {
    #[cfg(feature = "kbs")]
    {
        use crate::plugins::kbs::{KBS_ADDR_ENV_KEY, KBS_PRIVATE_KEY_PATH_ENV_KEY};

        env::set_var(
            KBS_PRIVATE_KEY_PATH_ENV_KEY,
            config.kbs_config.private_key_path,
        );
        env::set_var(KBS_ADDR_ENV_KEY, config.kbs_config.kbs_addr);
    }

    Server::builder()
        .add_service(KeyProviderServiceServer::new(KeyProvider::new()?))
        .serve(config.socket)
        .await?;
    Ok(())
}
