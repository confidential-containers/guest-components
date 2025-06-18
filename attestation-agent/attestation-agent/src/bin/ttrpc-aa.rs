// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use attestation_agent::{AttestationAPIs, AttestationAgent};
use base64::Engine;
use clap::{arg, command, Parser};
use const_format::concatcp;
use log::{debug, info};
use std::{collections::HashMap, path::Path, sync::Arc};
use tokio::signal::unix::{signal, SignalKind};
use ttrpc::asynchronous::{Server, Service};
use ttrpc_dep::server::AA;

use crate::ttrpc_dep::ttrpc_protocol::attestation_agent_ttrpc::create_attestation_agent_service;

mod ttrpc_dep;

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

    /// Initdata digest to be verified by AA. If initdata check failed, AA will failed to launch.
    /// The initdata should be base64 standard encoding.
    ///
    /// Example:
    /// `--initdata_digest AAAAAAAAAAAA`
    #[arg(short, long)]
    initdata_digest: Option<String>,
}

pub fn start_ttrpc_service(aa: AttestationAgent) -> Result<HashMap<String, Service>> {
    let service = AA { inner: aa };
    let service = Arc::new(service);
    let get_resource_service = create_attestation_agent_service(service);
    Ok(get_resource_service)
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
    if let Some(initdata) = cli.initdata_digest {
        info!("Initdata digest is given by parameter, try to check.");
        let initdata = base64::engine::general_purpose::STANDARD
            .decode(&initdata)
            .context("base64 decode initdata")?;
        let res = aa.bind_init_data(&initdata).await.context(
            "The initdata supplied by the parameter is inconsistent with that of the current platform.",
        )?;
        match res {
            attester::InitDataResult::Ok => info!("Check initdata passed."),
            attester::InitDataResult::Unsupported => {
                info!("Platform does not support initdata checking. Jumping.")
            }
        }
    }

    aa.init().await.context("init AA")?;
    let att = start_ttrpc_service(aa)?;

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
