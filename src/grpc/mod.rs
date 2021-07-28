// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use log::*;
use std::net::SocketAddr;
use std::str;
use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};

use crate::kbc_runtime;
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
    async fn un_wrap_key(
        &self,
        request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        debug!("The UnWrapKey API is called...");

        // Deserialize and parse the gRPC input to get KBC name, KBS uri and annotation.
        let input_payload: InputPayload = parse_input(
            request.into_inner().key_provider_key_wrap_protocol_input,
        )
        .map_err(|e| {
            error!("Parse request failed: {}", e);
            Status::internal(format!(
                "[ERROR:attestation-agent] Parse request failed: {}",
                e
            ))
        })?;

        // Pass the KBC name, KBS uri and annotation to the KBC instance for content parsing and field decryption.
        let kbc_runtime_mutex_clone = Arc::clone(&kbc_runtime::KBC_RUNTIME);
        let mut kbc_runtime = kbc_runtime_mutex_clone.lock().map_err(|e| {
            error!("Get KBC runtime MUTEX failed: {}", e);
            Status::internal(format!(
                "[ERROR:attestation-agent] Get KBC runtime failed: {}",
                e
            ))
        })?;

        debug!("Call KBC to decrypt...");
        let decrypted_optsdata = kbc_runtime
            .decrypt(
                input_payload.kbc_name,
                input_payload.kbs_uri,
                input_payload.annotation,
            )
            .map_err(|e| {
                error!("Call KBC to decrypt failed: {}", e);
                Status::internal(format!(
                    "[ERROR:attestation-agent] KBC decryption failed: {}",
                    e
                ))
            })?;
        debug!("Decrypted successfully, get the plain PLBCO");

        // Construct output structure and serialize it as the return value of gRPC
        let output_struct = KeyUnwrapOutput {
            keyunwrapresults: KeyUnwrapResults {
                optsdata: decrypted_optsdata,
            },
        };
        let output = serde_json::to_string(&output_struct)
            .unwrap()
            .as_bytes()
            .to_vec();

        debug!("UnWrapKey API output:");
        debug!("{}", serde_json::to_string_pretty(&output_struct).unwrap());

        let reply = KeyProviderKeyWrapProtocolOutput {
            key_provider_key_wrap_protocol_output: output,
        };
        debug!("Reply successfully!");

        Ok(Response::new(reply))
    }

    async fn wrap_key(
        &self,
        _request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        debug!("The WrapKey API is called...");
        debug!("WrapKey API is unimplemented!");
        Err(Status::unimplemented(
            "WrapKey API of attestation-agent is unimplemented!",
        ))
    }
}

struct InputPayload {
    kbc_name: String,
    kbs_uri: String,
    annotation: String,
}

fn parse_input(input_byte: Vec<u8>) -> Result<InputPayload> {
    let input_string = String::from_utf8(input_byte)?;
    let input: KeyProviderInput = serde_json::from_str::<KeyProviderInput>(&input_string)?;
    debug!("UnWrapKey API Request Input");
    debug!("{}", serde_json::to_string_pretty(&input).unwrap());
    let base64_annotation = input
        .keyunwrapparams
        .annotation
        .ok_or_else(|| anyhow!("The annotation field in the input is Empty!"))?;
    let vec_annotation = base64::decode(base64_annotation)?;
    let jsonstring_annotation: &str = str::from_utf8(&vec_annotation)?;
    let dc = input
        .keyunwrapparams
        .dc
        .ok_or_else(|| anyhow!("The Dc field in the input is None!"))?;

    /*
     * AA expects the received DC parameter format is:
     * "dc":{
     *     "Parameters":{
     *         "attestation_agent":["< KBC_NAME::KBS_URI (base64encode) >"]
     *     }
     * }
     */
    let parameters_list = dc.parameters.get("attestation-agent").ok_or(anyhow!(
        "Invalid parameters: the request is not sent to attention agent!"
    ))?;
    let kbc_kbs_pair_byte = base64::decode(parameters_list[0].clone())?;
    let kbc_kbs_pair = std::str::from_utf8(&kbc_kbs_pair_byte)?;
    if let Some(index) = kbc_kbs_pair.find("::") {
        let kbc_name: String = kbc_kbs_pair[..index].to_string();
        let kbs_uri: String = kbc_kbs_pair[(index + 2)..].to_string();
        debug!("Get KBC_NAME:{}, KBS_URI:{}", kbc_name, kbs_uri);
        return Ok(InputPayload {
            kbc_name: kbc_name,
            kbs_uri: kbs_uri,
            annotation: jsonstring_annotation.to_string(),
        });
    } else {
        return Err(anyhow!(
            "Invalid parameters: invalid {} pair format!",
            kbc_kbs_pair
        ));
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
