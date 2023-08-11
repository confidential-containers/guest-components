// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use clap::Parser;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use std::net::SocketAddr;

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

async fn api_handler(_req: Request<Body>) -> Result<Response<Body>> {
    Ok(Response::new(Body::empty()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("Starting API server on {}", args.bind);

    let address: SocketAddr = args.bind.parse().expect("Failed to parse the address");

    let api_service = make_service_fn(|_conn: &AddrStream| {
        async move { Ok::<_, GenericError>(service_fn(api_handler)) }
    });

    let server = Server::bind(&address).serve(api_service);

    println!("API Server listening on http://{}", args.bind);

    if let Err(e) = server.await {
        eprintln!("API server error: {}", e);
    }

    Ok(())
}
