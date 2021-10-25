// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::enc_mods;
use anyhow::*;
use log::*;
use std::net::SocketAddr;
use tonic::{transport::Server, Request, Response, Status};

use key_provider::key_provider_service_server::{KeyProviderService, KeyProviderServiceServer};
use key_provider::{KeyProviderKeyWrapProtocolInput, KeyProviderKeyWrapProtocolOutput};
use protocol::keyprovider_structs::*;

pub mod protocol;
pub mod key_provider {
    tonic::include_proto!("keyprovider");
}

#[derive(Debug, Default)]
pub struct KeyProvider {}

#[tonic::async_trait]
impl KeyProviderService for KeyProvider {
    async fn wrap_key(
        &self,
        request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        let input_string =
            String::from_utf8(request.into_inner().key_provider_key_wrap_protocol_input).unwrap();
        debug!("WrapKey API Request Input: {}", input_string);
        let input: KeyProviderInput =
            serde_json::from_str::<KeyProviderInput>(&input_string).unwrap();
        let optsdata = input.keywrapparams.optsdata.unwrap();
        let params: Vec<String> = input
            .keywrapparams
            .ec
            .unwrap()
            .parameters
            .get("attestation-agent")
            .unwrap()
            .iter()
            // According to
            // https://github.com/containers/ocicrypt/blob/e4a936881fb7cf4b2b8fe49e81b8232fd4c48e97/config/constructors.go#L112,
            // this Vec will only have one element anyways, but let's decode all elements of it
            // just to be sure.
            .map(|p| String::from_utf8(base64::decode(p).unwrap()).unwrap())
            .collect();

        let annotation: String =
            enc_mods::enc_optsdata_gen_anno(&base64::decode(optsdata).unwrap(), params).unwrap();

        let output_struct = KeyWrapOutput {
            keywrapresults: KeyWrapResults {
                annotation: annotation.as_bytes().to_vec(),
            },
        };
        let output = serde_json::to_string(&output_struct)
            .unwrap()
            .as_bytes()
            .to_vec();
        debug!(
            "WrapKey API output: {}",
            serde_json::to_string(&output_struct).unwrap()
        );
        let reply = KeyProviderKeyWrapProtocolOutput {
            key_provider_key_wrap_protocol_output: output,
        };
        debug!("Reply successfully!");

        Ok(Response::new(reply))
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

pub async fn start_service(socket: SocketAddr) -> Result<()> {
    let service = KeyProvider::default();
    let _server = Server::builder()
        .add_service(KeyProviderServiceServer::new(service))
        .serve(socket)
        .await?;
    Ok(())
}
