// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use attestation_agent::{config::Config, AttestationAgent};
use clap::Parser;
use const_format::concatcp;
use shadow_rs::shadow;
use std::{collections::HashMap, path::Path, sync::Arc};
use tokio::signal::unix::{signal, SignalKind};
use tracing::{debug, info};
use tracing_subscriber::{fmt::Subscriber, EnvFilter};
use ttrpc::asynchronous::{Server, Service};
use ttrpc_dep::server::AA;

use protos::ttrpc::aa::attestation_agent_ttrpc::create_attestation_agent_service;

shadow!(build);

mod ttrpc_dep;

const DEFAULT_UNIX_SOCKET_DIR: &str = "/run/confidential-containers/attestation-agent/";
const UNIX_SOCKET_PREFIX: &str = "unix://";
const DEFAULT_ATTESTATION_SOCKET_ADDR: &str = concatcp!(
    UNIX_SOCKET_PREFIX,
    DEFAULT_UNIX_SOCKET_DIR,
    "attestation-agent.sock"
);

const FEATURE_INFO: &str = include_str!(concat!(env!("OUT_DIR"), "/version"));
const DIRTY_SUFFIX: &str = if build::GIT_CLEAN { "" } else { " (dirty)" };
const VERSION: &str = concatcp!(
    build::LAST_TAG,
    "-",
    build::SHORT_COMMIT,
    DIRTY_SUFFIX,
    "\n",
    FEATURE_INFO
);

#[derive(Debug, Parser)]
#[command(author, version = VERSION)]
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

    /// Path to the Initdata TOML file. The initdata plaintext will be carried in the attestation process.
    ///
    /// Note that the initdata digest will not be checked against the platform's initdata status.
    ///
    /// Example:
    /// `--initdata_toml /path/to/initdata.toml`
    #[arg(short = 't', long)]
    initdata_toml: Option<String>,
}

pub fn start_ttrpc_service(aa: AttestationAgent) -> Result<HashMap<String, Service>> {
    let service = AA { inner: aa };
    let service = Arc::new(service);
    let get_resource_service = create_attestation_agent_service(service);
    Ok(get_resource_service)
}

#[tokio::main]
pub async fn main() -> Result<()> {
    let cli = Cli::parse();

    let (config, config_log) = Config::from_file(cli.config_file)?;

    let env_filter = match std::env::var_os("RUST_LOG") {
        Some(_) => EnvFilter::try_from_default_env().context("RUST_LOG is present but invalid")?,
        None => EnvFilter::try_new(&config.log.level)
            .context(format!("Invalid log level: {}", config.log.level))?,
    };

    let version = format!(
        r"
  ___   _    _              _          _    _                     ___                       _   
 / _ \ | |  | |            | |        | |  (_)                   / _ \                     | |  
/ /_\ \| |_ | |_  ___  ___ | |_  __ _ | |_  _   ___   _ __      / /_\ \  __ _   ___  _ __  | |_ 
|  _  || __|| __|/ _ \/ __|| __|/ _` || __|| | / _ \ | '_ \     |  _  | / _` | / _ \| '_ \ | __|
| | | || |_ | |_|  __/\__ \| |_| (_| || |_ | || (_) || | | |    | | | || (_| ||  __/| | | || |_ 
\_| |_/ \__| \__|\___||___/ \__|\__,_| \__||_| \___/ |_| |_|    \_| |_/ \__, | \___||_| |_| \__|
                                                                         __/ |                  
                                                                        |___/                                                                  
version: {VERSION}
buildtime: {}
loglevel: {env_filter}
rpc: ttrpc
",
        build::BUILD_TIME,
    );

    Subscriber::builder().with_env_filter(env_filter).init();

    info!("Welcome to Confidential Containers Attestation Agent (ttRPC version)!\n\n{version}");

    info!("{config_log}");
    debug!(config = ?config, "Using config");

    if !Path::new(DEFAULT_UNIX_SOCKET_DIR).exists() {
        std::fs::create_dir_all(DEFAULT_UNIX_SOCKET_DIR).expect("Create unix socket dir failed");
    }

    clean_previous_sock_file(&cli.attestation_sock)
        .context("clean previous attestation socket file")?;

    let mut aa = AttestationAgent::new(config).context("start AA")?;

    if let Some(initdata_toml_path) = cli.initdata_toml {
        info!("Initdata TOML file is given by parameter");
        let initdata_toml =
            std::fs::read_to_string(&initdata_toml_path).context("read initdata toml file")?;
        aa.set_initdata_toml(initdata_toml);
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
