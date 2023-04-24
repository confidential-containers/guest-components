// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use ::ttrpc::asynchronous::Server;
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

pub async fn ttrpc_main() -> Result<()> {
    let app_matches = App::new(rpc::AGENT_NAME)
            .version(env!("CARGO_PKG_VERSION"))
            .about(rpc::ABOUT.as_str())
            .arg(
                Arg::with_name("KeyProvider ttRPC Unix socket addr")
                    .long("keyprovider_sock")
                    .takes_value(true)
                    .help("This Unix socket address which the KeyProvider ttRPC service will listen to, for example: --keyprovider_sock unix:///tmp/aa_keyprovider",
                    ),
            )
            .arg(
                Arg::with_name("GetResource ttRPC Unix socket addr")
                    .long("getresource_sock")
                    .takes_value(true)
                    .help("This Unix socket address which the GetResource ttRPC service will listen to, for example: --getresource_sock unix:///tmp/aa_getresource",
                    ),
            )
            .get_matches();

    if !Path::new(DEFAULT_UNIX_SOCKET_DIR).exists() {
        std::fs::create_dir_all(DEFAULT_UNIX_SOCKET_DIR).expect("Create unix socket dir failed");
    }

    let keyprovider_socket = app_matches
        .value_of("KeyProvider ttRPC Unix socket addr")
        .unwrap_or(DEFAULT_KEYPROVIDER_SOCKET_ADDR);

    let getresource_socket = app_matches
        .value_of("GetResource ttRPC Unix socket addr")
        .unwrap_or(DEFAULT_GETRESOURCE_SOCKET_ADDR);

    clean_previous_sock_file(keyprovider_socket)
        .context("clean previous keyprovider socket file")?;
    clean_previous_sock_file(getresource_socket)
        .context("clean previous getresource socket file")?;

    let kp = rpc::keyprovider::ttrpc::start_ttrpc_service()?;
    let gs = rpc::getresource::ttrpc::start_ttrpc_service()?;
    let mut kps = Server::new()
        .bind(getresource_socket)
        .context("cannot bind getresource ttrpc service")?
        .register_service(gs);

    kps.start().await?;

    let mut gss = Server::new()
        .bind(keyprovider_socket)
        .context("cannot bind keyprovider ttrpc service")?
        .register_service(kp);

    gss.start().await?;

    debug!(
        "KeyProvider ttRPC service listening on: {:?}",
        keyprovider_socket
    );
    debug!(
        "GetResource ttRPC service listening on: {:?}",
        getresource_socket
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
