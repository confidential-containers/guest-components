// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This tool is to test ttrpc Confidential Data Hub

#![allow(non_snake_case)]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Args, Parser, Subcommand};
use confidential_data_hub::storage::volume_type::Storage;
use protos::{
    api::*,
    api_ttrpc::{
        GetResourceServiceClient, ImagePullServiceClient, SealedSecretServiceClient,
        SecureMountServiceClient,
    },
    keyprovider::*,
    keyprovider_ttrpc::KeyProviderServiceClient,
};
use ttrpc::context;

mod protos;

const NANO_PER_SECOND: i64 = 1000 * 1000 * 1000;

#[derive(Parser)]
#[command(name = "cdh_client_ttrpc")]
#[command(bin_name = "cdh_client_ttrpc")]
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

    /// Pull image
    PullImage(PullImageArgs),
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

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct PullImageArgs {
    /// Reference of the image
    #[arg(short, long)]
    image_url: String,

    /// Path to store the image bundle
    #[arg(short, long)]
    bundle_path: String,
}
pub struct ImagePullService {
    client_image_pull: ImagePullServiceClient,
    client_unwrap_key: KeyProviderServiceClient,
    timeout_image_pull: i64,
}
impl ImagePullService {
    fn new(cdh_addr: &str, timeout: i64) -> Self {
        let inner = ttrpc::asynchronous::Client::connect(cdh_addr).expect("connect ttrpc socket");
        let client_image_pull = ImagePullServiceClient::new(inner.clone());
        let client_unwrap_key = KeyProviderServiceClient::new(inner.clone());
        let timeout_image_pull = timeout * NANO_PER_SECOND;
        ImagePullService {
            client_image_pull,
            client_unwrap_key,
            timeout_image_pull,
        }
    }
    async fn pull_image(&self, image_path: &str, bundle_path: &str) -> Result<String> {
        let req = ImagePullRequest {
            image_url: image_path.to_string(),
            bundle_path: bundle_path.to_string(),
            ..Default::default()
        };
        print!("seding pull image request to CDH: {:?}\n", req);
        let res = self
            .client_image_pull
            .pull_image(ttrpc::context::with_timeout(self.timeout_image_pull), &req)
            .await?;
        println!("CDH pull image response: {:?}\n", res.manifest_digest);
        Ok(res.manifest_digest)
    }
    async fn unwrap_key(&self, annotation_path: &str) -> Result<String> {
        let KeyProviderKeyWrapProtocolInput =
            tokio::fs::read(annotation_path).await.expect("read file");
        let req = KeyProviderKeyWrapProtocolInput {
            KeyProviderKeyWrapProtocolInput,
            ..Default::default()
        };
        let res = self
            .client_unwrap_key
            .un_wrap_key(context::with_timeout(self.timeout_image_pull), &req)
            .await
            .expect("request to CDH");
        let res = STANDARD.encode(res.KeyProviderKeyWrapProtocolOutput);
        println!("{res}");
        Ok(res)
    }
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let cdh_addr = &args.socket;
    let image_pull_timeout = &args.timeout * NANO_PER_SECOND;
    let image_pull_service = ImagePullService::new(cdh_addr, image_pull_timeout);
    //use another inner for other services just use once
    let inner = ttrpc::asynchronous::Client::connect(cdh_addr).expect("connect ttrpc socket");
    //finish cli operation
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
            let res = image_pull_service
                .unwrap_key(&arg.annotation_path)
                .await
                .expect("unwrap key");
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
            let storage_manifest: Vec<u8> =
                tokio::fs::read(arg.storage_path).await.expect("read file");
            let storage: Storage =
                serde_json::from_slice(&storage_manifest).expect("deserialize Storage");
            let req = SecureMountRequest {
                volume_type: storage.volume_type,
                flags: storage.flags,
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
        Operation::PullImage(arg) => {
            let res = image_pull_service
                .pull_image(&arg.image_url, &arg.bundle_path)
                .await
                .expect("pull image");
            println!("image pull success{}", res);
        }
    }
    //TODO: start a server and wait for guest cvm to do image_pull and memory map//
}
