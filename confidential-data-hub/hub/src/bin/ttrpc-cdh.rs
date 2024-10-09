// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{env, path::Path, sync::Arc};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use confidential_data_hub::CdhConfig;
use log::info;
use protos::{
    api_ttrpc::{
        create_get_resource_service, create_image_pull_service, create_sealed_secret_service,
        create_secure_mount_service,
    },
    keyprovider_ttrpc::create_key_provider_service,
};
use tokio::{
    fs,
    signal::unix::{signal, SignalKind},
};
use ttrpc::r#async::Server as TtrpcServer;
use ttrpc_server::Server;

mod message;
mod protos;
mod ttrpc_server;

const UNIX_SOCKET_PREFIX: &str = "unix://";

const VERSION: &str = include_str!(concat!(env!("OUT_DIR"), "/version"));

#[derive(Debug, Parser)]
#[command(author, version = Some(VERSION))]
struct Cli {
    /// Path to the config  file
    ///
    /// `--config /etc/confidential-data-hub.conf`
    #[arg(short)]
    config: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let cli = Cli::parse();

    let config = CdhConfig::new(cli.config)?;

    let unix_socket_path = config
        .socket
        .strip_prefix(UNIX_SOCKET_PREFIX)
        .ok_or_else(|| anyhow!("socket address scheme is not expected"))?;

    create_socket_parent_directory(unix_socket_path).await?;
    clean_previous_sock_file(unix_socket_path).await?;

    let server = Server::new(&config).await.context("create CDH instance")?;
    let server = Arc::new(server);

    let mut server = TtrpcServer::new()
        .bind(&config.socket)
        .context("cannot bind cdh ttrpc service")?
        .register_service(create_sealed_secret_service(server.clone() as _))
        .register_service(create_get_resource_service(server.clone() as _))
        .register_service(create_key_provider_service(server.clone() as _))
        .register_service(create_secure_mount_service(server.clone() as _))
        .register_service(create_image_pull_service(server.clone() as _));

    info!(
        "[ttRPC] Confidential Data Hub starts to listen to request: {}",
        config.socket
    );
    server.start().await?;

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;
    tokio::select! {
        _ = hangup.recv() => {
            info!("Client terminal disconnected.");
            server.shutdown().await?;
        }
        _ = interrupt.recv() => {
            info!("SIGINT received, gracefully shutdown.");
            server.shutdown().await?;
        }
    };

    Ok(())
}

async fn clean_previous_sock_file(unix_socket_file: &str) -> Result<()> {
    if Path::new(unix_socket_file).exists() {
        fs::remove_file(unix_socket_file).await?;
    }

    Ok(())
}

async fn create_socket_parent_directory(unix_socket_file: &str) -> Result<()> {
    let file_path = Path::new(unix_socket_file);
    let parent_directory = file_path
        .parent()
        .ok_or(anyhow!("The file path does not have a parent directory."))?;
    fs::create_dir_all(parent_directory).await?;
    Ok(())
}
