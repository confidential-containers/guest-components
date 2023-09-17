// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{path::Path, sync::Arc};

use anyhow::{Context, Result};
use api_ttrpc::{
    create_get_public_key_service, create_get_resource_service, create_key_provider_service,
    create_sealed_secret_service, create_secure_mount_service,
};
use clap::Parser;
use log::info;
use server::Server;
use tokio::{
    fs,
    signal::unix::{signal, SignalKind},
};
use ttrpc::r#async::Server as TtrpcServer;

mod api;
mod api_ttrpc;
mod server;

const DEFAULT_UNIX_SOCKET_DIR: &str = "/run/confidential-containers";
const DEFAULT_CDH_SOCKET_ADDR: &str = "unix:///run/confidential-containers/cdh.sock";

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
    let cli = Cli::parse();

    if !Path::new(DEFAULT_UNIX_SOCKET_DIR).exists() {
        fs::create_dir_all(DEFAULT_UNIX_SOCKET_DIR)
            .await
            .context("create unix socket dir failed")?;
    }

    let sealed_secret_service = ttrpc_service!(create_sealed_secret_service);
    let get_resource_service = ttrpc_service!(create_get_resource_service);
    let key_provider_service = ttrpc_service!(create_key_provider_service);
    let secure_mount_service = ttrpc_service!(create_secure_mount_service);
    let get_publickey_service = ttrpc_service!(create_get_public_key_service);

    let mut server = TtrpcServer::new()
        .bind(&cli.socket)
        .context("cannot bind cdh ttrpc service")?
        .register_service(sealed_secret_service)
        .register_service(get_resource_service)
        .register_service(secure_mount_service)
        .register_service(key_provider_service)
        .register_service(get_publickey_service);

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
