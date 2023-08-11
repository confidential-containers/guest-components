// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use clap::Parser;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use std::net::SocketAddr;
use std::sync::Arc;

mod router;
mod utils;
use crate::router::Router;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;

const DEFAULT_BIND: &str = "127.0.0.1:8006";

/// API Server arguments info.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Bind address for API Server
    #[arg(default_value_t = DEFAULT_BIND.to_string(), short, long = "bind")]
    bind: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("Starting API server on {}", args.bind);

    let address: SocketAddr = args.bind.parse().expect("Failed to parse the address");

    let router = Router::new();
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

    println!("API Server listening on http://{}", args.bind);

    if let Err(e) = server.await {
        eprintln!("API server error: {}", e);
    }

    Ok(())
}
