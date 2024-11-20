// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This tool is to test gRPC Confidential Data Hub

#![allow(non_snake_case)]

use api::{
    get_resource_service_client::GetResourceServiceClient,
    key_provider_service_client::KeyProviderServiceClient,
    sealed_secret_service_client::SealedSecretServiceClient,
    secure_mount_service_client::SecureMountServiceClient, GetResourceRequest,
    KeyProviderKeyWrapProtocolInput, SecureMountRequest, UnsealSecretInput,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Args, Parser, Subcommand};
use confidential_data_hub::storage::volume_type::Storage;

mod api {
    tonic::include_proto!("api");
    tonic::include_proto!("keyprovider");
}

#[derive(Parser)]
#[command(name = "cdh_client_grpc")]
#[command(bin_name = "cdh_client_grpc")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    operation: Operation,

    /// gRPC socket
    #[arg(short, long, default_value_t = String::from("http://127.0.0.1:50000"))]
    socket: String,
}

#[derive(Subcommand)]
#[command(author, version, about, long_about = None)]
enum Operation {
    /// Unseal the given sealed secret
    UnsealSecret(UnsealSecretArgs),

    /// Unwrap the image encryption key
    UnwrapKey(UnwrapKeyArgs),

    /// Get Resource from KBS
    GetResource(GetResourceArgs),

    /// Secure mount
    SecureMount(SecureMountArgs),
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct UnsealSecretArgs {
    /// path to the file which contains the sealed secret
    #[arg(short, long)]
    secret_path: String,
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct UnwrapKeyArgs {
    /// path to the file which contains the AnnotationPacket
    #[arg(short, long)]
    annotation_path: String,
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct GetResourceArgs {
    /// KBS Resource URI to the target resource
    #[arg(short, long)]
    resource_uri: String,
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct SecureMountArgs {
    /// path to the file which contains the Storage object.
    #[arg(short, long)]
    storage_path: String,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    match args.operation {
        Operation::UnsealSecret(arg) => {
            let mut client = SealedSecretServiceClient::connect(args.socket)
                .await
                .expect("initialize client");
            let secret = tokio::fs::read(arg.secret_path).await.expect("read file");
            let req = tonic::Request::new(UnsealSecretInput { secret });
            let res = client.unseal_secret(req).await.expect("request to CDH");
            let res = STANDARD.encode(res.into_inner().plaintext);
            println!("{res}");
        }
        Operation::UnwrapKey(arg) => {
            let mut client = KeyProviderServiceClient::connect(args.socket)
                .await
                .expect("initialize client");
            let key_provider_key_wrap_protocol_input = tokio::fs::read(arg.annotation_path)
                .await
                .expect("read file");
            let req = tonic::Request::new(KeyProviderKeyWrapProtocolInput {
                key_provider_key_wrap_protocol_input,
            });
            let res = client.un_wrap_key(req).await.expect("request to CDH");
            let res = STANDARD.encode(res.into_inner().key_provider_key_wrap_protocol_output);
            println!("{res}");
        }
        Operation::GetResource(arg) => {
            let mut client = GetResourceServiceClient::connect(args.socket)
                .await
                .expect("initialize client");
            let req = tonic::Request::new(GetResourceRequest {
                resource_path: arg.resource_uri,
            });
            let res = client.get_resource(req).await.expect("request to CDH");
            let res = STANDARD.encode(res.into_inner().resource);
            println!("{res}");
        }
        Operation::SecureMount(arg) => {
            let mut client = SecureMountServiceClient::connect(args.socket)
                .await
                .expect("initialize client");
            let storage_manifest = tokio::fs::read(arg.storage_path).await.expect("read file");
            let storage: Storage =
                serde_json::from_slice(&storage_manifest).expect("deserialize Storage");
            let req = tonic::Request::new(SecureMountRequest {
                volume_type: storage.volume_type,
                flags: storage.flags,
                options: storage.options,
                mount_point: storage.mount_point,
            });
            let res = client.secure_mount(req).await.expect("request to CDH");
            println!("mount path: {}", res.into_inner().mount_path);
        }
    }
}
