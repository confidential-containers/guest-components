// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use ::ttrpc::asynchronous::Server;
use clap::{arg, command, Parser};
use const_format::concatcp;
use std::path::Path;
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::Mutex,
};

const DEFAULT_UNIX_SOCKET_DIR: &str = "/run/confidential-containers/attestation-agent/";
const UNIX_SOCKET_PREFIX: &str = "unix://";
const DEFAULT_KEYPROVIDER_SOCKET_ADDR: &str = concatcp!(
    UNIX_SOCKET_PREFIX,
    DEFAULT_UNIX_SOCKET_DIR,
    "keyprovider.sock"
);
const DEFAULT_GETRESOURCE_SOCKET_ADDR: &str = concatcp!(
    UNIX_SOCKET_PREFIX,
    DEFAULT_UNIX_SOCKET_DIR,
    "getresource.sock"
);

lazy_static! {
    pub static ref ASYNC_ATTESTATION_AGENT: Arc<Mutex<AttestationAgent>> =
        Arc::new(Mutex::new(AttestationAgent::new()));
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// KeyProvider ttRPC Unix socket addr.
    ///
    /// This Unix socket address which the KeyProvider ttRPC service
    /// will listen to, for example:
    ///
    /// `--keyprovider_sock unix:///tmp/aa_keyprovider`
    #[arg(default_value_t = DEFAULT_KEYPROVIDER_SOCKET_ADDR.to_string(), short, long)]
    keyprovider_sock: String,

    /// GetResource ttRPC Unix socket addr.
    ///
    /// This Unix socket address which the GetResource ttRPC service
    /// will listen to, for example:
    ///
    /// `--getresource_sock unix:///tmp/aa_getresource`
    #[arg(default_value_t = DEFAULT_GETRESOURCE_SOCKET_ADDR.to_string(), short, long)]
    getresource_sock: String,
}

pub async fn ttrpc_main() -> Result<()> {
    let cli = Cli::parse();

    if !Path::new(DEFAULT_UNIX_SOCKET_DIR).exists() {
        std::fs::create_dir_all(DEFAULT_UNIX_SOCKET_DIR).expect("Create unix socket dir failed");
    }

    clean_previous_sock_file(&cli.keyprovider_sock)
        .context("clean previous keyprovider socket file")?;
    clean_previous_sock_file(&cli.getresource_sock)
        .context("clean previous getresource socket file")?;

    let kp = rpc::keyprovider::ttrpc::start_ttrpc_service()?;
    let gs = rpc::getresource::ttrpc::start_ttrpc_service()?;
    let mut kps = Server::new()
        .bind(&cli.getresource_sock)
        .context("cannot bind getresource ttrpc service")?
        .register_service(gs);

    kps.start().await?;

    let mut gss = Server::new()
        .bind(&cli.keyprovider_sock)
        .context("cannot bind keyprovider ttrpc service")?
        .register_service(kp);

    gss.start().await?;

    debug!(
        "KeyProvider ttRPC service listening on: {:?}",
        cli.keyprovider_sock
    );
    debug!(
        "GetResource ttRPC service listening on: {:?}",
        cli.getresource_sock
    );

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;
    tokio::select! {
        _ = hangup.recv() => {
            info!("Client terminal disconnected.");
            kps.shutdown().await?;
            gss.shutdown().await?;
        }
        _ = interrupt.recv() => {
            info!("SIGINT received, gracefully shutdown.");
            kps.shutdown().await?;
            gss.shutdown().await?;
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
