// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::net::SocketAddr;

use anyhow::anyhow;
use clap::Parser;
use serde::Deserialize;

const DEFAULT_SOCKET: &str = "127.0.0.1:50000";

/// Contains all configurable CoCoKeyprovider properties.
#[derive(Clone, Debug, Deserialize)]
pub struct CoCoKeyproviderConfig {
    /// KBS provider configurations
    #[cfg(feature = "kbs")]
    pub kbs_config: crate::plugins::kbs::Config,

    /// Socket addresses (IP:port) to listen on, e.g. 127.0.0.1:50000.
    pub socket: SocketAddr,
}

impl TryFrom<&str> for CoCoKeyproviderConfig {
    type Error = anyhow::Error;

    /// Load `Config` from a configuration file. Supported formats are all formats supported by the
    /// `config` crate. See [`Config`] for schema information.
    fn try_from(config_path: &str) -> Result<Self, Self::Error> {
        let c = config::Config::builder()
            .set_default("sockets", vec![DEFAULT_SOCKET])?
            .add_source(config::File::with_name(config_path))
            .build()?;

        c.try_deserialize()
            .map_err(|e| anyhow!("invalid config: {}", e.to_string()))
    }
}

/// KBS command-line arguments.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to a CoCoKeyprovider config file. Supported formats: TOML, YAML, JSON and possibly other formats
    /// supported by the `config` crate.
    #[arg(short, long)]
    pub config_file: String,
}
