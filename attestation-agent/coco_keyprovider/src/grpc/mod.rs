// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::enc_mods::{crypto::Algorithm, enc_optsdata_gen_anno, kbs::get_kek, AnnotationPacket};
use anyhow::*;
use base64::Engine;
use jwt_simple::prelude::Ed25519KeyPair;
use log::*;
use protos::grpc::cdh::keyprovider::{
    key_provider_service_server::{KeyProviderService, KeyProviderServiceServer},
    KeyProviderKeyWrapProtocolInput, KeyProviderKeyWrapProtocolOutput,
};
use reqwest::Url;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::fs;
use tonic::{transport::Server, Request, Response, Status};

use protocol::keyprovider_structs::*;

pub mod protocol;

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
                "key_provider_key_wrap_protocol_input is not legal utf8 string: {e:?}"
            ))
        })?;

        debug!("WrapKey API Request Input: {}", input_string);
        let input: KeyProviderInput = serde_json::from_str::<KeyProviderInput>(&input_string)
            .map_err(|e| {
                Status::invalid_argument(format!("parse key provider input failed: {e:?}"))
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
            (&self.kbs, &self.auth_private_key),
            &engine
                .decode(optsdata)
                .map_err(|_| Status::aborted("base64 decode"))?,
            params,
        )
        .await
        .map_err(|e| Status::internal(format!("encrypt failed: {e:?}")))?;

        let output_struct = KeyWrapOutput {
            keywrapresults: KeyWrapResults {
                annotation: annotation.as_bytes().to_vec(),
            },
        };
        let output = serde_json::to_string(&output_struct)
            .map_err(|e| Status::internal(format!("serde json failed: {e:?}")))?
            .as_bytes()
            .to_vec();
        debug!(
            "WrapKey API output: {}",
            serde_json::to_string(&output_struct)
                .map_err(|e| Status::internal(format!("serde json failed: {e:?}")))?
        );
        let reply = KeyProviderKeyWrapProtocolOutput {
            key_provider_key_wrap_protocol_output: output,
        };
        debug!("Reply successfully!");

        Result::Ok(Response::new(reply))
    }

    async fn un_wrap_key(
        &self,
        request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        let input_string = String::from_utf8(
            request.into_inner().key_provider_key_wrap_protocol_input,
        )
        .map_err(|e| {
            Status::invalid_argument(format!(
                "key_provider_key_wrap_protocol_input is not legal utf8 string: {e:?}"
            ))
        })?;

        let input: KeyProviderInput = serde_json::from_str::<KeyProviderInput>(&input_string)
            .map_err(|e| {
                Status::invalid_argument(format!("parse key provider input failed: {e:?}"))
            })?;

        let annotation_base64 = input.keyunwrapparams.annotation.ok_or_else(|| {
            Status::invalid_argument("illegal keyunwrapparams without annotation")
        })?;

        let engine = base64::engine::general_purpose::STANDARD;
        let annotation_bytes = engine.decode(annotation_base64).map_err(|e| {
            Status::invalid_argument(format!("base64 decode annotation failed: {e:?}"))
        })?;

        let annotation: AnnotationPacket =
            serde_json::from_slice(&annotation_bytes).map_err(|e| {
                Status::invalid_argument(format!("parse annotation packet failed: {e:?}"))
            })?;

        let kbs_url = self.kbs.as_ref().ok_or_else(|| {
            Status::internal("KBS URL not configured. Please provide KBS URL to keyprovider.")
        })?;

        let (kbs_addr, kbs_path) = crate::enc_mods::normalize_path(&annotation.kid)
            .map_err(|e| Status::internal(format!("Failed to normalize key path: {:?}", e)))?;

        let kbs_url_with_addr = if kbs_addr.is_empty() {
            kbs_url.clone()
        } else {
            kbs_addr
                .parse::<Url>()
                .or_else(|_| format!("{}://{}", kbs_url.scheme(), kbs_addr).parse::<Url>())
                .map_err(|_| {
                    Status::internal(format!("Failed to parse KBS address: {}", kbs_addr))
                })?
        };

        let kek = get_kek(&kbs_url_with_addr, &kbs_path).await.map_err(|e| {
            error!(
                "Failed to get KEK from KBS for kid={}: {:?}",
                annotation.kid, e
            );
            Status::internal("Failed to get KEK from KBS")
        })?;

        let wrapped_data = engine
            .decode(&annotation.wrapped_data)
            .map_err(|e| Status::internal(format!("base64 decode wrapped_data failed: {e:?}")))?;

        let iv = engine
            .decode(&annotation.iv)
            .map_err(|e| Status::internal(format!("base64 decode iv failed: {e:?}")))?;

        let wrap_type: Algorithm = annotation
            .wrap_type
            .parse()
            .map_err(|e| Status::internal(format!("Failed to parse wrap_type: {:?}", e)))?;

        let optsdata = crate::enc_mods::crypto::decrypt(&wrapped_data, &kek, &iv, &wrap_type)
            .map_err(|e| {
                error!("Failed to decrypt key for kid={}: {:?}", annotation.kid, e);
                Status::internal("Failed to decrypt key")
            })?;

        let output_struct = KeyUnwrapOutput {
            keyunwrapresults: KeyUnwrapResults { optsdata },
        };
        let output = serde_json::to_string(&output_struct)
            .map_err(|e| Status::internal(format!("serde json failed: {e:?}")))?
            .as_bytes()
            .to_vec();

        let reply = KeyProviderKeyWrapProtocolOutput {
            key_provider_key_wrap_protocol_output: output,
        };

        Result::Ok(Response::new(reply))
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
