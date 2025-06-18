// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

mod server;

use anyhow::*;
use attestation_agent::{AttestationAPIs, AttestationAgent};
use base64::Engine;
use clap::Parser;
use log::{debug, info};
use tokio::signal::unix::{signal, SignalKind};

use std::net::SocketAddr;

const DEFAULT_ATTESTATION_AGENT_ADDR: &str = "127.0.0.1:50002";

const VERSION: &str = include_str!(concat!(env!("OUT_DIR"), "/version"));

#[derive(Debug, Parser)]
#[command(author, version = Some(VERSION))]
struct Cli {
    /// Attestation gRPC Unix socket addr.
    ///
    /// This Unix socket address which the Attestation gRPC service
    /// will listen to, for example:
    ///
    /// `--attestation_sock 127.0.0.1:11223`
    #[arg(default_value_t = DEFAULT_ATTESTATION_AGENT_ADDR.to_string(), short, long = "attestation_sock")]
    attestation_sock: String,

    /// Configuration file for Attestation Agent
    ///
    /// Example:
    /// `--config /etc/attestation-agent.conf`
    #[arg(short, long)]
    config_file: Option<String>,

    /// Initdata digest to be verified by AA. If initdata check failed, AA will failed to launch.
    /// The initdata should be base64 standard encoding.
    ///
    /// Example:
    /// `--initdata_digest AAAAAAAAAAAA`
    #[arg(short, long)]
    initdata_digest: Option<String>,
}

#[tokio::main]
pub async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let cli = Cli::parse();

    let attestation_socket = cli.attestation_sock.parse::<SocketAddr>()?;

    let mut aa = AttestationAgent::new(cli.config_file.as_deref()).context("start AA")?;
    if let Some(initdata) = cli.initdata_digest {
        info!("Initdata digest is given by parameter, try to check.");
        let initdata = base64::engine::general_purpose::STANDARD
            .decode(&initdata)
            .context("base64 decode initdata")?;
        let res = aa
            .bind_init_data(&initdata)
            .await
            .context("The initdata supplied by the parameter is inconsistent with that of the current platform.")?;
        match res {
            attester::InitDataResult::Ok => info!("Check initdata passed."),
            attester::InitDataResult::Unsupported => {
                info!("Platform does not support initdata checking. Jumping.")
            }
        }
    }

    aa.init().await.context("init AA")?;
    debug!(
        "Attestation gRPC service listening on: {:?}",
        cli.attestation_sock
    );

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;
    tokio::select! {
        _ = hangup.recv() => info!("Client terminal disconnected."),
        _ = interrupt.recv() => info!("SIGINT received, gracefully shutdown."),
        _ = server::start_grpc_service(attestation_socket, aa) => info!("AA exits."),
    }

    Ok(())
}
