// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{env, net::SocketAddr};

use anyhow::{Context, Result};
use clap::Parser;
use confidential_data_hub::hub::Hub;
use log::info;
use tokio::signal::unix::{signal, SignalKind};

mod config;
mod grpc_server;
mod message;

use config::*;

const DEFAULT_CONFIG_PATH: &str = "/etc/confidential-data-hub.conf";

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

fn get_config_path(cli: Cli) -> String {
    cli.config.unwrap_or_else(|| {
        if let Ok(env_path) = env::var("CDH_CONFIG_PATH") {
            return env_path;
        }
        DEFAULT_CONFIG_PATH.into()
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let cli = Cli::parse();
    let config_path = get_config_path(cli);
    info!("Use configuration file {}", config_path);

    let config = CdhConfig::init(&config_path).await?;
    config.set_configuration_envs();

    let cdh_socket = config.socket.parse::<SocketAddr>()?;

    info!(
        "[gRPC] Confidential Data Hub starts to listen to request: {}",
        config.socket
    );

    let credentials = config
        .credentials
        .iter()
        .map(|it| (it.path.clone(), it.resource_uri.clone()))
        .collect();

    let cdh = Hub::new(credentials).await.context("start CDH")?;

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;
    tokio::select! {
        _ = hangup.recv() => info!("Client terminal disconnected."),
        _ = interrupt.recv() => info!("SIGINT received, gracefully shutdown."),
        _ = grpc_server::start_grpc_service(cdh_socket, cdh) => info!("CDH exits."),
    }

    Ok(())
}
