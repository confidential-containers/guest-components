// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use clap::{arg, command, Parser};
use log::*;
use std::{net::SocketAddr, path::PathBuf};

pub mod enc_mods;
pub mod grpc;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Socket address (IP:port) to listen to, e.g. 127.0.0.1:50000.
    #[arg(required = true, short, long)]
    socket: SocketAddr,

    /// Private key used to authenticate the resource registration endpoint token (JWT)
    /// to Key Broker Service. This key can sign legal JWTs. If both `kbs`
    /// and this field are given, the automatic registration will be
    /// enabled.
    #[arg(short, long)]
    auth_private_key: Option<PathBuf>,

    /// Address of Key Broker Service. If both `auth_private_key` and
    /// this field are specified, the keys generated to encrypt an image
    /// will be automatically registered into the KBS.
    #[arg(long)]
    kbs: Option<SocketAddr>,
}

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

    let cli = Cli::parse();

    debug!("starting keyprovider gRPC service...");
    info!("listening to socket addr: {:?}", cli.socket);

    grpc::start_service(socket).await?;

    Ok(())
}
