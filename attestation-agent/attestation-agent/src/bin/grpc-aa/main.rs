// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

mod server;

use anyhow::*;
use attestation_agent::{config::Config, AttestationAgent};
use clap::Parser;
use const_format::concatcp;
use shadow_rs::shadow;
use std::net::SocketAddr;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{debug, info};
use tracing_subscriber::{fmt::Subscriber, EnvFilter};

shadow!(build);

const DEFAULT_ATTESTATION_AGENT_ADDR: &str = "127.0.0.1:50002";

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

    /// Path to the Initdata TOML file. The initdata plaintext will be carried in the attestation process.
    ///
    /// Note that the initdata digest will not be checked against the platform's initdata status.
    ///
    /// Example:
    /// `--initdata_toml /path/to/initdata.toml`
    #[arg(short = 't', long)]
    initdata_toml: Option<String>,
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
rpc: grpc
",
        build::BUILD_TIME,
    );

    Subscriber::builder().with_env_filter(env_filter).init();

    info!("Welcome to Confidential Containers Attestation Agent (gRPC version)!\n\n{version}");
    info!("{config_log}");
    debug!(config = ?config, "Using config");

    let attestation_socket = cli.attestation_sock.parse::<SocketAddr>()?;

    let mut aa = AttestationAgent::new(config).context("start AA")?;

    if let Some(initdata_toml_path) = cli.initdata_toml {
        info!("Initdata TOML file is given by parameter");
        let initdata_toml =
            std::fs::read_to_string(&initdata_toml_path).context("read initdata toml file")?;
        aa.set_initdata_toml(initdata_toml);
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
