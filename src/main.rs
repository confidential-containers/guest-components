// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate lazy_static;
use anyhow::*;
use clap::{App, Arg};
use log::*;
use std::net::SocketAddr;

pub mod grpc;
pub mod kbc_modules;
pub mod kbc_runtime;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let app_matches = App::new(grpc::AGENT_NAME)
        .version("1.0.0")
        .arg(
            Arg::with_name("socket addr")
                .long("grpc_sock")
                .takes_value(true)
                .help("The socket address which the grpc service will listen to, for example: --grpc_sock 127.0.0.1:11223",
                ),
        )
        .get_matches();

    let socket = app_matches
        .value_of("socket addr")
        .unwrap_or("127.0.0.0:44444")
        .parse::<SocketAddr>()?;

    debug!("starting keyprovider gRPC service...");
    debug!("listening to socket addr: {:?}", socket);

    grpc::start_service(socket).await?;

    Ok(())
}
