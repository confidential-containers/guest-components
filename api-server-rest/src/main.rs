// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use clap::Parser;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use shadow_rs::shadow;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::{fmt::Subscriber, EnvFilter};

shadow!(build);

mod client;
mod router;
mod utils;

use router::Router;

use crate::client::aa::AAClient;
use crate::client::cdh::CDHClient;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;

pub const TTRPC_TIMEOUT: i64 = 50 * 1000 * 1000 * 1000;
const DEFAULT_BIND: &str = "127.0.0.1:8006";
const DEFAULT_FEATURE: &str = "resource";
const CDH_ADDR: &str = "unix:///run/confidential-containers/cdh.sock";
const AA_ADDR: &str =
    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

const VERSION: &str = include_str!(concat!(env!("OUT_DIR"), "/guest_components_version"));

/// API Server arguments info.
#[derive(Parser, Debug)]
#[command(author, version = Some(VERSION), about, long_about = None)]
struct Args {
    /// Bind address for API Server
    #[arg(default_value_t = DEFAULT_BIND.to_string(), short, long = "bind")]
    bind: String,

    /// Features for rest API Server, allowed options: resource, attestation, all
    #[arg(default_value_t = DEFAULT_FEATURE.to_string(), short, long = "features")]
    features: String,

    /// Listen address of confidential-data-hub TTRPC Service
    #[arg(default_value_t = CDH_ADDR.to_string(), short, long = "cdh_addr")]
    cdh_addr: String,

    /// Listen address of attestation-agent TTRPC Service
    #[arg(default_value_t = AA_ADDR.to_string(), short, long = "aa_addr")]
    aa_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = match std::env::var_os("RUST_LOG") {
        Some(_) => EnvFilter::try_from_default_env().expect("RUST_LOG is present but invalid"),
        None => EnvFilter::new("info"),
    };

    Subscriber::builder().with_env_filter(env_filter).init();

    let args = Args::parse();

    info!(
        "Starting API server on {} with features {}",
        args.bind, args.features
    );

    let address: SocketAddr = args.bind.parse().expect("Failed to parse the address");

    let (aa_client, cdh_client) = match args.features.as_str() {
        "resource" => (None, Some(CDHClient::new(&args.cdh_addr).await?)),
        "attestation" => (Some(AAClient::new(&args.aa_addr).await?), None),
        "all" => (
            Some(AAClient::new(&args.aa_addr).await?),
            Some(CDHClient::new(&args.cdh_addr).await?),
        ),
        _ => {
            error!("Unknown features. Supported features are: resource, attestation, all.");
            std::process::exit(1);
        }
    };
    let router = Router::new(aa_client, cdh_client, args.features);

    let router = Arc::new(tokio::sync::Mutex::new(router));

    let api_service = make_service_fn(|conn: &AddrStream| {
        let remote_addr = conn.remote_addr();
        let local_router = router.clone();

        async move {
            Ok::<_, GenericError>(service_fn(move |req| {
                let local_router = local_router.clone();
                async move { local_router.lock().await.route(remote_addr, req).await }
            }))
        }
    });

    let server = Server::bind(&address).serve(api_service);

    info!("API Server listening on http://{}", args.bind);

    if let Err(e) = server.await {
        error!("API server error: {e}");
    }

    Ok(())
}
