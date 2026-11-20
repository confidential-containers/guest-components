// Copyright (c) 2023 by Alibaba.
// Copyright (c) 2024 Red Hat, Inc
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Attest and fetch confidential resources from Trustee

use anyhow::Context;
use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use clap::{Parser, Subcommand};
use shadow_rs::{formatcp, shadow};
use std::fs;
use std::path::PathBuf;
use tracing::debug;
use tracing_subscriber::{EnvFilter, fmt::Subscriber};

use kbs_protocol::KbsClientBuilder;
use kbs_protocol::KbsClientCapabilities;
use kbs_protocol::ResourceUri;
use kbs_protocol::evidence_provider::{EvidenceProvider, NativeEvidenceProvider};
use kbs_protocol::token_provider::TestTokenProvider;

shadow!(build);

const CLI_VERSION: &str = formatcp!("{}-{}", build::LAST_TAG, build::SHORT_COMMIT);

#[derive(Parser)]
#[command(version = CLI_VERSION)]
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
    /// Attest and print the TEE key and token as Base64-encoded JSON
    Attest {
        /// Initdata string
        #[clap(long)]
        initdata: Option<String>,
    },

    /// Get confidential resource
    #[clap(arg_required_else_help = true)]
    GetResource {
        /// KBS Resource path of format <repository>/<type>/<tag>
        /// Document: https://github.com/confidential-containers/guest-components/blob/main/attestation-agent/docs/RESOURCE_URI.md
        #[clap(long, value_parser)]
        path: String,

        /// Initdata string
        #[clap(long)]
        initdata: Option<String>,

        /// Base64-encoded JSON key and token returned by the attest command
        #[clap(long, value_name = "BASE64_JSON", conflicts_with = "initdata")]
        attestation_result: Option<String>,
    },
}

#[derive(serde::Deserialize, serde::Serialize)]
struct AttestationResult {
    key: String,
    token: String,
}

fn encode_attestation_result(key: &str, token: &str) -> Result<String> {
    let json = serde_json::to_vec(&AttestationResult {
        key: key.to_string(),
        token: token.to_string(),
    })?;
    Ok(STANDARD.encode(json))
}

fn decode_attestation_result(encoded: &str) -> Result<AttestationResult> {
    let json = STANDARD
        .decode(encoded)
        .context("failed to decode Base64 attestation result")?;
    serde_json::from_slice(&json).context("failed to parse attestation result JSON")
}

fn attesting_client_builder(
    url: &str,
    cert: Option<&str>,
) -> Result<KbsClientBuilder<Box<dyn EvidenceProvider>>> {
    let evidence_provider: Box<dyn EvidenceProvider> = Box::new(NativeEvidenceProvider::new()?);
    let mut client_builder = KbsClientBuilder::with_evidence_provider(evidence_provider, url);

    #[cfg(feature = "pqc-experimental")]
    {
        client_builder =
            client_builder.set_tee_key_algorithm(kbs_protocol::TeeKeyAlgorithm::MlKem768A192Kw);
    }

    if let Some(cert) = cert {
        client_builder = client_builder.add_kbs_cert(cert);
    }

    Ok(client_builder)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let env_filter = match std::env::var_os("RUST_LOG") {
        Some(_) => EnvFilter::try_from_default_env().expect("RUST_LOG is present but invalid"),
        None => EnvFilter::new("info"),
    };

    Subscriber::builder()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let url = cli.url;
    let cert_file = cli.cert_file;

    debug!("url {url}");
    debug!("cert_file {cert_file:?}");

    let cert = if let Some(cf) = cert_file {
        debug!("Reading certificate from cert_file {}", cf.display());
        Some(fs::read_to_string(cf)?)
    } else {
        None
    };

    match cli.command {
        Commands::Attest { initdata } => {
            let mut client_builder = attesting_client_builder(&url, cert.as_deref())?;
            if let Some(init) = initdata {
                client_builder = client_builder.add_initdata(init);
            }
            let mut client = client_builder.build()?;

            let (token, key) = client.get_token().await?;
            let key = key.to_pem()?;
            println!(
                "{}",
                encode_attestation_result(key.as_str(), &token.content)?
            );
        }
        Commands::GetResource {
            path,
            initdata,
            attestation_result,
        } => {
            let resource_uri = if path.contains("://") {
                path
            } else {
                format!("kbs:///{}", path.trim_start_matches('/'))
            };
            let resource = ResourceUri::try_from(resource_uri.as_str())
                .map_err(|e| anyhow::anyhow!(e))
                .context("failed to parse ResourceUri")?;

            let resource_bytes = if let Some(encoded) = attestation_result {
                let AttestationResult { key, token } = decode_attestation_result(&encoded)?;
                let token_provider = Box::<TestTokenProvider>::default();
                let mut client_builder =
                    KbsClientBuilder::with_token_provider(token_provider, &url)
                        .set_token(&token)
                        .set_tee_key(&key);

                if let Some(cert) = cert.as_deref() {
                    client_builder = client_builder.add_kbs_cert(cert);
                }

                let mut client = client_builder.build()?;
                client.get_resource(resource).await?
            } else {
                let mut client_builder = attesting_client_builder(&url, cert.as_deref())?;
                if let Some(init) = initdata {
                    client_builder = client_builder.add_initdata(init);
                }
                let mut client = client_builder.build()?;

                let (_token, _key) = client.get_token().await?; // attest first
                client.get_resource(resource).await?
            };

            println!("{}", STANDARD.encode(resource_bytes));
        }
    };

    Ok(())
}
