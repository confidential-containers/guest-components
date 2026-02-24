// Copyright (c) 2023 by Alibaba.
// Copyright (c) 2024 Red Hat, Inc
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Attest and fetch confidential resources from Trustee

use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use tracing::debug;
use tracing_subscriber::{fmt::Subscriber, EnvFilter};

use kbs_protocol::evidence_provider::NativeEvidenceProvider;
use kbs_protocol::KbsClientBuilder;
use kbs_protocol::KbsClientCapabilities;
use kbs_protocol::ResourceUri;

#[derive(Parser)]
struct Cli {
    /// Trustee URL of format <protocol>://<host>:<port>
    #[clap(long, value_parser)]
    url: String,

    /// Trustee https certificate file path (PEM format)
    #[clap(long, value_parser)]
    cert_file: Option<PathBuf>,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Get confidential resource
    #[clap(arg_required_else_help = true)]
    GetResource {
        /// KBS Resource path of format <repository>/<type>/<tag>
        /// Document: https://github.com/confidential-containers/guest-components/blob/main/attestation-agent/docs/KBS_URI.md
        #[clap(long, value_parser)]
        path: String,

        /// Initdata string
        #[clap(long)]
        initdata: Option<String>,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let env_filter = match std::env::var_os("RUST_LOG") {
        Some(_) => EnvFilter::try_from_default_env().expect("RUST_LOG is present but invalid"),
        None => EnvFilter::new("info"),
    };

    Subscriber::builder().with_env_filter(env_filter).init();

    let cli = Cli::parse();

    let url = cli.url;
    let cert_file = cli.cert_file;

    debug!("url {url}");
    debug!("cert_file {cert_file:?}");

    // Native evidence provider
    let evidence_provider = Box::new(NativeEvidenceProvider::new()?);

    // a kbs_protocol client with evidence_provider
    let mut client_builder = KbsClientBuilder::with_evidence_provider(evidence_provider, &url);

    // if a certificate is given, use it
    if let Some(cf) = cert_file {
        debug!("Reading certificate from cert_file {}", cf.display());
        let cert = fs::read_to_string(cf)?;
        client_builder = client_builder.add_kbs_cert(&cert)
    }

    match cli.command {
        Commands::GetResource { path, initdata } => {
            // resource_path should start with '/' but not with '//'
            let resource_path = match path.starts_with('/') {
                false => format!("/{path}"),
                true => path,
            };

            if let Some(init) = initdata {
                client_builder = client_builder.add_initdata(init);
            }
            let mut client = client_builder.build()?;

            let resource = ResourceUri::new("", &resource_path)?;
            let (_token, _key) = client.get_token().await?; // attest first
            let resource_bytes = client.get_resource(resource).await?;

            println!("{}", STANDARD.encode(resource_bytes));
        }
    };

    Ok(())
}
