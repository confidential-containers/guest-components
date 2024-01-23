// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{path::Path, sync::Arc};

use anyhow::{anyhow, Context, Result};
use api_ttrpc::{
    create_get_resource_service, create_sealed_secret_service, create_secure_mount_service,
};
use clap::Parser;
use keyprovider_ttrpc::create_key_provider_service;
use log::info;
use server::Server;
use tokio::{
    fs,
    signal::unix::{signal, SignalKind},
};
use ttrpc::r#async::Server as TtrpcServer;

mod api;
mod api_ttrpc;
mod keyprovider;
mod keyprovider_ttrpc;
mod server;

const DEFAULT_CDH_SOCKET_ADDR: &str = "unix:///run/confidential-containers/cdh.sock";

const UNIX_SOCKET_PREFIX: &str = "unix://";

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// CDH ttRPC Unix socket addr.
    ///
    /// CDH will listen to this unix socket address.
    ///
    /// `--socket unix:///tmp/cdh_keyprovider`
    #[arg(default_value_t = DEFAULT_CDH_SOCKET_ADDR.to_string(), short)]
    socket: String,
}

macro_rules! ttrpc_service {
    ($func: expr) => {{
        let server = Server::new().await?;
        let server = Arc::new(Box::new(server) as _);
        $func(server)
    }};
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let cli = Cli::parse();

    let unix_socket_path = cli
        .socket
        .strip_prefix(UNIX_SOCKET_PREFIX)
        .ok_or_else(|| anyhow!("socket address scheme is not expected"))?;

    create_socket_parent_directory(unix_socket_path).await?;
    clean_previous_sock_file(unix_socket_path).await?;

    let sealed_secret_service = ttrpc_service!(create_sealed_secret_service);
    let get_resource_service = ttrpc_service!(create_get_resource_service);
    let key_provider_service = ttrpc_service!(create_key_provider_service);
    let secure_mount_service = ttrpc_service!(create_secure_mount_service);
    let mut server = TtrpcServer::new()
        .bind(&cli.socket)
        .context("cannot bind cdh ttrpc service")?
        .register_service(sealed_secret_service)
        .register_service(get_resource_service)
        .register_service(secure_mount_service)
        .register_service(key_provider_service);

    info!(
        "Confidential Data Hub starts to listen to request: {}",
        cli.socket
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
