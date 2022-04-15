// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use clap::{App, Arg};
use log::*;
use std::net::SocketAddr;

pub mod enc_mods;
pub mod grpc;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let app_matches = App::new("sample_keyprovider")
        .version("1.0.0")
        .arg(
            Arg::with_name("socket addr")
                .long("keyprovider_sock")
                .takes_value(true)
                .help(
                    "The socket address which the grpc service will listen to, 
                    for example: --keyprovider_sock 127.0.0.1:11223",
                ),
        )
        .get_matches();

    let socket = app_matches
        .value_of("socket addr")
        .unwrap_or("127.0.0.1:50000")
        .parse::<SocketAddr>()?;

    debug!("starting keyprovider gRPC service...");
    debug!("listening to socket addr: {:?}", socket);

    grpc::start_service(socket).await?;

    Ok(())
}
