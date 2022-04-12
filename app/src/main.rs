// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate lazy_static;

use anyhow::*;
use attestation_agent::AttestationAgent;
use clap::{App, Arg};
use log::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

mod grpc;

lazy_static! {
    pub static ref ATTESTATION_AGENT: Arc<Mutex<AttestationAgent>> =
        Arc::new(Mutex::new(AttestationAgent::new()));
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let app_matches = App::new(grpc::AGENT_NAME)
        .version("1.0.0")
        .arg(
            Arg::with_name("KeyProvider gRPC socket addr")
                .long("keyprovider_sock")
                .takes_value(true)
                .help("This socket address which the KeyProvider gRPC service will listen to, for example: --keyprovider_sock 127.0.0.1:11223",
                ),
        )
        .arg(
            Arg::with_name("GetResource gRPC socket addr")
                .long("getresource_sock")
                .takes_value(true)
                .help("This socket address which the GetResource gRPC service will listen to, for example: --getresource_sock 127.0.0.1:11223",
                ),
        )
        .get_matches();

    let keyprovider_socket = app_matches
        .value_of("KeyProvider gRPC socket addr")
        .unwrap_or("127.0.0.0:44444")
        .parse::<SocketAddr>()?;

    let getresource_socket = app_matches
        .value_of("GetResource gRPC socket addr")
        .unwrap_or("127.0.0.0:55555")
        .parse::<SocketAddr>()?;

    debug!(
        "KeyProvider gRPC service listening on: {:?}",
        keyprovider_socket
    );
    debug!(
        "GetResource gRPC service listening on: {:?}",
        getresource_socket
    );

    let keyprovider_server = grpc::keyprovider::start_service(keyprovider_socket);
    let getresource_server = grpc::getresource::start_service(getresource_socket);

    tokio::join!(keyprovider_server, getresource_server).0
}
