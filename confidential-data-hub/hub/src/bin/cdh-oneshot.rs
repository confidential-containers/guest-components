// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a one-shot version of CDH

#![allow(non_snake_case)]

use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Args, Parser, Subcommand};
use confidential_data_hub::{hub::Hub, storage::volume_type::Storage, DataHub};
use tracing::{debug, info, warn};
use tracing_subscriber::{fmt::Subscriber, EnvFilter};

mod config;
#[derive(Parser)]
#[command(name = "cdh_oneshot")]
#[command(bin_name = "cdh_oneshot")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    operation: Operation,

    /// CDH's config path
    #[arg(short, long)]
    config: Option<String>,

    /// Retries times
    #[arg(short, long, default_value = "3")]
    retry: u32,
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
    /// URL of the image to be pulled
    #[arg(short, long)]
    image_url: String,

    /// Path to store the bundle
    #[arg(short, long)]
    bundle_path: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let (config, config_log) = config::read_config(cli.config).expect("failed to read config");

    let env_filter = match std::env::var_os("RUST_LOG") {
        Some(_) => EnvFilter::try_from_default_env().expect("RUST_LOG is present but invalid"),
        None => EnvFilter::try_new(&config.log.level)
            .expect(&format!("Invalid log level: {}", config.log.level)),
    };

    Subscriber::builder().with_env_filter(env_filter).init();

    info!("{config_log}");
    debug!(config = ?config, "Using config");
    let cdh = Hub::new(config).await.expect("failed to start CDH");

    let mut tried = 1;
    match cli.operation {
        Operation::UnsealSecret(op_args) => {
            let secret = tokio::fs::read(op_args.secret_path)
                .await
                .expect("read secret file");
            loop {
                match cdh.unseal_secret(secret.clone()).await {
                    Ok(secret) => {
                        let res = STANDARD.encode(secret);
                        println!("{res}");
                        break;
                    }
                    Err(e) => {
                        if tried > cli.retry {
                            let error = format!("failed to unseal secret, {e:?}");
                            panic!("{error}");
                        }
                        warn!("Tried {tried} times... failed to unseal secret: {e}.");
                        tried += 1;
                    }
                }
            }
        }
        Operation::UnwrapKey(op_args) => {
            let KeyProviderKeyWrapProtocolInput = tokio::fs::read(op_args.annotation_path)
                .await
                .expect("read annotation packet file");
            loop {
                match cdh.unwrap_key(&KeyProviderKeyWrapProtocolInput).await {
                    Ok(KeyProviderKeyWrapProtocolOutput) => {
                        let res = STANDARD.encode(KeyProviderKeyWrapProtocolOutput);
                        println!("{res}");
                        break;
                    }
                    Err(e) => {
                        if tried > cli.retry {
                            panic!("failed to unwrap key");
                        }
                        warn!("Tried {tried} times... failed to unwrap key: {e}.");
                        tried += 1;
                    }
                }
            }
        }
        Operation::GetResource(op_args) => loop {
            match cdh.get_resource(op_args.resource_uri.clone()).await {
                Ok(resource) => {
                    let res = STANDARD.encode(resource);
                    println!("{res}");
                    break;
                }
                Err(e) => {
                    if tried > cli.retry {
                        let error = format!("failed to get resource, {e:?}");
                        panic!("{error}");
                    }
                    warn!("Tried {tried} times... failed to get resource: {e}.");
                    tried += 1;
                }
            }
        },
        Operation::SecureMount(op_args) => {
            let storage_manifest = tokio::fs::read(op_args.storage_path)
                .await
                .expect("read file");
            let storage: Storage =
                serde_json::from_slice(&storage_manifest).expect("deserialize Storage");
            let res = cdh
                .secure_mount(storage)
                .await
                .expect("failed to secure mount");
            println!("mount path: {res}");
        }
        Operation::PullImage(op_args) => {
            let manifest_digest = cdh
                .pull_image(&op_args.image_url, &op_args.bundle_path)
                .await
                .expect("failed to pull image");
            println!("image digest: {manifest_digest}");
        }
    }
}
