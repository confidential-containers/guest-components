// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use clap::Parser;
use daemonize::Daemonize;
use log::*;
use std::{fs::File, net::SocketAddr, path::PathBuf};
use tokio::fs;

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
    kbs: Option<String>,

    /// Whether this process is launched in daemon mode. If it is set to
    /// true, the stdio and stderr will be redirected to
    /// `/run/confidential-containers/coco_keyprovider.out` and
    /// `/run/confidential-containers/coco_keyprovider.err`.
    /// The pid will be recorded in
    /// `/run/confidential-containers/coco_keyprovider.pid`
    #[arg(short, long, default_value = "false")]
    daemon: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();

    debug!("starting keyprovider gRPC service...");
    info!("listening to socket addr: {:?}", cli.socket);

    if cli.auth_private_key.is_some() && cli.kbs.is_some() {
        info!(
            "The encryption key will be registered to kbs: {:?}",
            cli.kbs
        );
    }

    if cli.daemon {
        fs::create_dir_all("/run/confidential-containers")
            .await
            .context("create coco run dir failed.")?;
        let stdout = File::create("/run/confidential-containers/coco_keyprovider.out")
            .context("create stdout redirect file failed.")?;
        let stderr = File::create("/run/confidential-containers/coco_keyprovider.err")
            .context("create stderr redirect file failed.")?;

        let daemonize = Daemonize::new()
            .pid_file("/run/confidential-containers/coco_keyprovider.pid")
            .chown_pid_file(true)
            .working_directory("/run/confidential-containers")
            .stdout(stdout)
            .stderr(stderr);

        daemonize.start().context("daemonize failed")?;
    }

    grpc::start_service(cli.socket, cli.auth_private_key, cli.kbs).await?;

    Ok(())
}
