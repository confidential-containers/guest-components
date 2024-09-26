// Copyright (c) 2023 by Alibaba.
// Copyright (c) 2024 Red Hat, Inc
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A simple client for fetching resources from Trustee.

use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::{Parser, Subcommand};
use log::debug;

use kbs_protocol::evidence_provider::NativeEvidenceProvider;
use kbs_protocol::KbsClientBuilder;
use kbs_protocol::KbsClientCapabilities;

pub mod tcconfig;
use tcconfig::TrusteeClientConfig;

#[derive(Parser)]
struct Cli {
    /// A configuration file for trustee-client (default is /etc/trustee-client.conf)
    #[clap(long, value_parser)]
    config_file: Option<String>,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Get confidential resource
    #[clap(arg_required_else_help = true)]
    GetResource {
        /// KBS Resource path, e.g my_repo/resource_type/123abc
        /// Document: https://github.com/confidential-containers/attestation-agent/blob/main/docs/KBS_URI.md
        #[clap(long, value_parser)]
        path: String,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();

    let tcc = TrusteeClientConfig::new(cli.config_file)?;

    let url = tcc.url.clone();
    let cert = tcc.get_cert();

    debug!("url {}", url);
    debug!("cert {:?}", cert);

    let evidence_provider = Box::new(NativeEvidenceProvider::new()?);

    // build a kbs_protocol client with evidence_provider
    let mut client_builder = KbsClientBuilder::with_evidence_provider(evidence_provider, &url);

    // if a certificate is given, use it
    if let Some(c) = cert {
        client_builder = client_builder.add_kbs_cert(&c)
    }

    // Build the client. This client is used throughout the program
    let mut client = client_builder.build()?;

    match cli.command {
        Commands::GetResource { path } => {
            // get resource
            let resource_uri = format!("kbs:///{}", path);
            let resource_bytes = client
                .get_resource(serde_json::from_str(&format!("\"{resource_uri}\""))?)
                .await?;

            println!("{}", STANDARD.encode(resource_bytes));
        }
    };

    Ok(())
}
