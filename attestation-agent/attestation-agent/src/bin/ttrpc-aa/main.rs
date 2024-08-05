// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use ::ttrpc::asynchronous::Server;
use anyhow::*;
use attestation_agent::AttestationAgent;
use clap::{arg, command, Parser};
use const_format::concatcp;
use log::{debug, info};
use std::path::Path;
use tokio::signal::unix::{signal, SignalKind};

mod server;
mod ttrpc_protocol;

const DEFAULT_UNIX_SOCKET_DIR: &str = "/run/confidential-containers/attestation-agent/";
const UNIX_SOCKET_PREFIX: &str = "unix://";
const DEFAULT_ATTESTATION_SOCKET_ADDR: &str = concatcp!(
    UNIX_SOCKET_PREFIX,
    DEFAULT_UNIX_SOCKET_DIR,
    "attestation-agent.sock"
);

const VERSION: &str = include_str!(concat!(env!("OUT_DIR"), "/version"));

#[derive(Debug, Parser)]
#[command(author, version = Some(VERSION))]
struct Cli {
    /// Attestation ttRPC Unix socket addr.
    ///
    /// This Unix socket address which the Attestation ttRPC service
    /// will listen to, for example:
    ///
    /// `--attestation_sock unix:///tmp/attestation`
    #[arg(default_value_t = DEFAULT_ATTESTATION_SOCKET_ADDR.to_string(), short, long = "attestation_sock")]
    attestation_sock: String,

    /// Configuration file for Attestation Agent
    ///
    /// Example:
    /// `--config /etc/attestation-agent.conf`
    #[arg(short, long)]
    config_file: Option<String>,
}

#[tokio::main]
pub async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let cli = Cli::parse();

    if !Path::new(DEFAULT_UNIX_SOCKET_DIR).exists() {
        std::fs::create_dir_all(DEFAULT_UNIX_SOCKET_DIR).expect("Create unix socket dir failed");
    }

    clean_previous_sock_file(&cli.attestation_sock)
        .context("clean previous attestation socket file")?;

    let mut aa = AttestationAgent::new(cli.config_file.as_deref()).context("start AA")?;
    aa.init().await.context("init AA")?;
    let att = server::start_ttrpc_service(aa)?;

    let mut atts = Server::new()
        .bind(&cli.attestation_sock)
        .context("cannot bind attestation ttrpc service")?
        .register_service(att);

    atts.start().await?;
    debug!(
        "Attestation ttRPC service listening on: {:?}",
        cli.attestation_sock
    );

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;
    tokio::select! {
        _ = hangup.recv() => {
            info!("Client terminal disconnected.");
            atts.shutdown().await?;
        }
        _ = interrupt.recv() => {
            info!("SIGINT received, gracefully shutdown.");
            atts.shutdown().await?;
        }
    };

    Ok(())
}

fn clean_previous_sock_file(unix_socket: &str) -> Result<()> {
    let path = unix_socket
        .strip_prefix(UNIX_SOCKET_PREFIX)
        .ok_or_else(|| anyhow!("socket address scheme is not expected"))?;

    if Path::new(path).exists() {
        std::fs::remove_file(path)?;
    }

    Ok(())
}
