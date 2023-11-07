// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use clap::Parser;
use log::*;

use crate::config::{Cli, CoCoKeyproviderConfig};

mod config;
pub mod encrypt;
pub mod grpc;
mod plugins;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();

    debug!("starting keyprovider gRPC service...");
    let config = CoCoKeyproviderConfig::try_from(&cli.config_file[..])?;

    info!("listening to socket addr: {}", config.socket);

    grpc::start_service(config).await?;

    Ok(())
}
