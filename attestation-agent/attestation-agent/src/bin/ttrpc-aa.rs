// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use attestation_agent::{AttestationAPIs, AttestationAgent, config::Config, initdata::Initdata};
use base64::Engine;
use clap::Parser;
use const_format::concatcp;
use shadow_rs::shadow;
use std::{collections::HashMap, path::Path, sync::Arc};
use tokio::signal::unix::{SignalKind, signal};
use tracing::{debug, info};
use tracing_subscriber::{EnvFilter, fmt::Subscriber};
use ttrpc::asynchronous::{Server, Service};
use ttrpc_dep::server::AA;

use protos::ttrpc::aa::attestation_agent_ttrpc::create_attestation_agent_service;

shadow!(build);

mod ttrpc_dep;

const UNIX_SOCKET_PREFIX: &str = "unix://";
const DEFAULT_ATTESTATION_SOCKET_ADDR: &str = concatcp!(
    UNIX_SOCKET_PREFIX,
    "/run/confidential-containers/attestation-agent/attestation-agent.sock"
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

    /// Initdata digest to be verified by AA. If initdata check failed, AA will failed to launch.
    /// The initdata should be base64 standard encoding.
    ///
    /// Note that this is an alternative to `--initdata_toml`.
    ///
    /// If both parameters `--initdata_toml` and `initdata_digest` are provided, parameter
    /// `--initdata_toml` takes precedence.
    ///
    /// Example:
    /// `--initdata_digest AAAAAAAAAAAA`
    #[arg(short, long)]
    initdata_digest: Option<String>,

    /// Path to the Initdata TOML file to be verified by AA. If initdata check failed, AA will failed to launch.
    /// The initdata should be base64 standard encoding.
    ///
    /// Note that this is an alternative to `--initdata_digest`.
    ///
    /// /// If both parameters `--initdata_toml` and `initdata_digest` are provided, parameter
    /// `--initdata_toml` takes precedence.
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

    let sock_path = cli
        .attestation_sock
        .strip_prefix(UNIX_SOCKET_PREFIX)
        .context("socket address scheme is not expected")?
        .to_owned();
    let sock_path_buf = Path::new(&sock_path);
    if !sock_path_buf.is_absolute() {
        bail!("attestation_sock path must be absolute, got: {sock_path}");
    }
    let sock_dir = sock_path_buf
        .parent()
        .context("attestation_sock path has no parent directory")?;
    if !sock_dir.exists() {
        std::fs::create_dir_all(sock_dir).context("create unix socket parent dir")?;
    } else {
        clean_previous_sock_file(sock_path_buf)
            .context("clean previous attestation socket file")?;
    }

    let mut aa = AttestationAgent::new(config).context("start AA")?;

    let mut initdata_digest = None;
    if let Some(initdata_toml_path) = cli.initdata_toml {
        info!("Initdata TOML file is given by parameter");
        let initdata_toml =
            std::fs::read_to_string(&initdata_toml_path).context("read initdata toml file")?;
        let (_, digest) = Initdata::parse_and_get_digest(&initdata_toml)?;
        aa.set_initdata_toml(initdata_toml);
        initdata_digest = Some(digest);
    } else if let Some(initdata) = cli.initdata_digest {
        info!("Initdata digest is given by parameter");
        let initdata = base64::engine::general_purpose::STANDARD
            .decode(&initdata)
            .context("base64 decode initdata")?;
        initdata_digest = Some(initdata);
    }

    if let Some(initdata_digest) = initdata_digest {
        let res = aa.bind_init_data(&initdata_digest).await.context(
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

/// Remove a leftover socket file from a previous run.
///
/// Only removes the file when it already exists **and** is a Unix socket.
/// Returns an error if the path exists but is not a socket (e.g. a regular
/// file or a directory), so callers are not surprised by silent data loss.
fn clean_previous_sock_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let file_type = path
        .metadata()
        .context("stat previous socket path")?
        .file_type();

    if std::os::unix::fs::FileTypeExt::is_socket(&file_type) {
        std::fs::remove_file(path).context("remove previous socket file")?;
    } else {
        bail!(
            "attestation_sock path '{}' already exists and is not a Unix socket",
            path.display()
        );
    }

    Ok(())
}
