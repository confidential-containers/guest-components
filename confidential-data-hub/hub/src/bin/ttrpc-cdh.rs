// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{path::Path, sync::Arc};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use const_format::concatcp;
use tracing::{debug, info};

use protos::ttrpc::cdh::{
    api_ttrpc::{
        create_get_resource_service, create_image_pull_service, create_sealed_secret_service,
        create_secure_mount_service,
    },
    keyprovider_ttrpc::create_key_provider_service,
};
use shadow_rs::shadow;
use tokio::{
    fs,
    signal::unix::{signal, SignalKind},
};
use tracing_subscriber::{fmt::Subscriber, EnvFilter};
use ttrpc::r#async::Server as TtrpcServer;
use ttrpc_server::Server;

shadow!(build);

mod config;
mod message;
mod ttrpc_server;

const UNIX_SOCKET_PREFIX: &str = "unix://";

const FEATURE_INFO: &str = include_str!(concat!(env!("OUT_DIR"), "/version"));
const DIRTY_SUFFIX: &str = if build::GIT_CLEAN { "" } else { " (dirty)" };
const VERSION: &str = concatcp!(
    build::LAST_TAG,
    "-",
    build::SHORT_COMMIT,
    DIRTY_SUFFIX,
    "\n",
    FEATURE_INFO,
);

#[derive(Debug, Parser)]
#[command(author, version = VERSION)]
struct Cli {
    /// Path to the config  file
    ///
    /// `--config /etc/confidential-data-hub.conf`
    #[arg(short)]
    config: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let (config, config_log) = config::read_config(cli.config).context("failed to read config")?;

    let env_filter = match std::env::var_os("RUST_LOG") {
        Some(_) => EnvFilter::try_from_default_env().context("RUST_LOG is present but invalid")?,
        None => EnvFilter::try_new(&config.log.level)
            .context(format!("Invalid log level: {}", config.log.level))?,
    };

    let version = format!(
        r"
 _____                 __  _      _               _    _         _   ______        _            _   _         _     
/  __ \               / _|(_)    | |             | |  (_)       | |  |  _  \      | |          | | | |       | |    
| /  \/  ___   _ __  | |_  _   __| |  ___  _ __  | |_  _   __ _ | |  | | | | __ _ | |_  __ _   | |_| | _   _ | |__  
| |     / _ \ | '_ \ |  _|| | / _` | / _ \| '_ \ | __|| | / _` || |  | | | |/ _` || __|/ _` |  |  _  || | | || '_ \ 
| \__/\| (_) || | | || |  | || (_| ||  __/| | | || |_ | || (_| || |  | |/ /| (_| || |_| (_| |  | | | || |_| || |_) |
 \____/ \___/ |_| |_||_|  |_| \__,_| \___||_| |_| \__||_| \__,_||_|  |___/  \__,_| \__|\__,_|  \_| |_/ \__,_||_.__/ 
                                                                                                                                                                                         
version: {VERSION}
buildtime: {}
loglevel: {env_filter}
rpc: ttrpc
",
        build::BUILD_TIME,
    );

    Subscriber::builder().with_env_filter(env_filter).init();

    info!("Welcome to Confidential Containers Confidential Data Hub (ttRPC version)!\n\n{version}");
    info!("{config_log}");
    debug!(config = ?config, "Using config");

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
