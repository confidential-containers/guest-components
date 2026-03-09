// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::net::SocketAddr;

use anyhow::{Context, Result};
use clap::Parser;
use confidential_data_hub::hub::Hub;
use shadow_rs::shadow;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{debug, info};
use tracing_subscriber::{fmt::Subscriber, EnvFilter};

shadow!(build);

mod config;
mod grpc_server;
mod message;

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
                                                                                                                                                                                         
version: v{}
commit: {}
buildtime: {}
loglevel: {env_filter}
rpc: grpc
",
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME,
    );

    Subscriber::builder().with_env_filter(env_filter).init();

    info!("Welcome to Confidential Containers Confidential Data Hub (gRPC version)!\n\n{version}");
    info!("{config_log}");
    debug!(config = ?config, "Using config");

    let cdh_socket = config.socket.parse::<SocketAddr>()?;

    let cdh = Hub::new(config).await.context("start CDH")?;

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;
    tokio::select! {
        _ = hangup.recv() => info!("Client terminal disconnected."),
        _ = interrupt.recv() => info!("SIGINT received, gracefully shutdown."),
        _ = grpc_server::start_grpc_service(cdh_socket, cdh) => info!("CDH exits."),
    }

    Ok(())
}
