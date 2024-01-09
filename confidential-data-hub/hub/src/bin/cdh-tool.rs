// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This tool is to test ttrpc Confidential Data Hub

#![allow(non_snake_case)]

use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Args, Parser, Subcommand};
use protos::{
    api::*,
    api_ttrpc::{GetResourceServiceClient, SealedSecretServiceClient, SecureMountServiceClient},
    keyprovider::*,
    keyprovider_ttrpc::KeyProviderServiceClient,
};
use storage::volume_type::Storage;
use ttrpc::context;

mod protos;

const NANO_PER_SECOND: i64 = 1000 * 1000 * 1000;

#[derive(Parser)]
#[command(name = "cdh_client")]
#[command(bin_name = "cdh_client")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    operation: Operation,

    /// ttrpc socket path
    #[arg(short, long, default_value_t = String::from("unix:///run/confidential-containers/cdh.sock"))]
    socket: String,

    /// request timeout (second)
    #[arg(short, long, default_value_t = 50)]
    timeout: i64,
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
    let inner = ttrpc::asynchronous::Client::connect(&args.socket).expect("connect ttrpc socket");

    match args.operation {
        Operation::UnsealSecret(arg) => {
            let client = SealedSecretServiceClient::new(inner);
            let secret = tokio::fs::read(arg.secret_path).await.expect("read file");
            let req = UnsealSecretInput {
                secret,
                ..Default::default()
            };
            let res = client
                .unseal_secret(context::with_timeout(args.timeout * NANO_PER_SECOND), &req)
                .await
                .expect("request to CDH");
            let res = STANDARD.encode(res.plaintext);
            println!("{res}");
        }
        Operation::UnwrapKey(arg) => {
            let client = KeyProviderServiceClient::new(inner);
            let KeyProviderKeyWrapProtocolInput = tokio::fs::read(arg.annotation_path)
                .await
                .expect("read file");
            let req = KeyProviderKeyWrapProtocolInput {
                KeyProviderKeyWrapProtocolInput,
                ..Default::default()
            };
            let res = client
                .un_wrap_key(context::with_timeout(args.timeout * NANO_PER_SECOND), &req)
                .await
                .expect("request to CDH");
            let res = STANDARD.encode(res.KeyProviderKeyWrapProtocolOutput);
            println!("{res}");
        }
        Operation::GetResource(arg) => {
            let client = GetResourceServiceClient::new(inner);
            let req = GetResourceRequest {
                ResourcePath: arg.resource_uri,
                ..Default::default()
            };
            let res = client
                .get_resource(context::with_timeout(args.timeout * NANO_PER_SECOND), &req)
                .await
                .expect("request to CDH");
            let res = STANDARD.encode(res.Resource);
            println!("{res}");
        }
        Operation::SecureMount(arg) => {
            let client = SecureMountServiceClient::new(inner);
            let storage_manifest = tokio::fs::read(arg.storage_path).await.expect("read file");
            let storage: Storage =
                serde_json::from_slice(&storage_manifest).expect("deserialize Storage");
            let req = SecureMountRequest {
                driver: storage.driver,
                driver_options: storage.driver_options,
                source: storage.source,
                fstype: storage.fstype,
                options: storage.options,
                mount_point: storage.mount_point,
                ..Default::default()
            };
            let res = client
                .secure_mount(context::with_timeout(args.timeout * NANO_PER_SECOND), &req)
                .await
                .expect("request to CDH");
            println!("mount path: {}", res.mount_path);
        }
    }
}
