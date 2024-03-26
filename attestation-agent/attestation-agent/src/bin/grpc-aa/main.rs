// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

mod server;

use anyhow::*;
use clap::Parser;
use log::{debug, info};
use tokio::signal::unix::{signal, SignalKind};

use std::net::SocketAddr;

const DEFAULT_ATTESTATION_AGENT_ADDR: &str = "127.0.0.1:50002";

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Attestation gRPC Unix socket addr.
    ///
    /// This Unix socket address which the Attestation gRPC service
    /// will listen to, for example:
    ///
    /// `--attestation_sock 127.0.0.1:11223`
    #[arg(default_value_t = DEFAULT_ATTESTATION_AGENT_ADDR.to_string(), short, long = "attestation_sock")]
    attestation_sock: String,
}

#[tokio::main]
pub async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let cli = Cli::parse();

    let attestation_socket = cli.attestation_sock.parse::<SocketAddr>()?;

    debug!(
        "Attestation gRPC service listening on: {:?}",
        cli.attestation_sock
    );

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;
    tokio::select! {
        _ = hangup.recv() => info!("Client terminal disconnected."),
        _ = interrupt.recv() => info!("SIGINT received, gracefully shutdown."),
        _ = server::start_grpc_service(attestation_socket) => info!("AA exits."),
    }

    Ok(())
}
