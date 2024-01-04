// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use clap::Parser;

use super::*;
use std::net::SocketAddr;

const DEFAULT_ATTESTATION_AGENT_ADDR: &str = "127.0.0.1:50002";

lazy_static! {
    pub static ref ASYNC_ATTESTATION_AGENT: Arc<tokio::sync::Mutex<AttestationAgent>> =
        Arc::new(tokio::sync::Mutex::new(AttestationAgent::new()));
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Attestation gRPC Unix socket addr.
    ///
    /// This Unix socket address which the Attestation ttRPC service
    /// will listen to, for example:
    ///
    /// `--attestation_sock 127.0.0.1:11223`
    #[arg(default_value_t = DEFAULT_ATTESTATION_AGENT_ADDR.to_string(), short, long = "attestation_sock")]
    attestation_sock: String,
}

pub async fn grpc_main() -> Result<()> {
    let cli = Cli::parse();

    let attestation_socket = cli.attestation_sock.parse::<SocketAddr>()?;

    debug!(
        "Attestation gRPC service listening on: {:?}",
        cli.attestation_sock
    );

    let attestation_server = rpc::attestation::grpc::start_grpc_service(attestation_socket);

    tokio::join!(attestation_server).0
}
