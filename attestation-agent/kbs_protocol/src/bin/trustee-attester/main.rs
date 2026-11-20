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
use kbs_types::Tee;

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
    },
}

/// The InitData to send with the attestation request.
///
/// On AWS Nitro Enclaves the InitData digest is carried in each attestation
/// document's `user_data`, bound inside the attestation-agent process that was
/// started with `--initdata-toml`. This separate process never binds it, so the
/// KBS would receive InitData its evidence does not carry and refuse it: say so
/// before attesting. Other TEEs keep InitData in a register set at launch,
/// which every process reports.
fn initdata_to_send(tee: Tee, initdata: Option<String>) -> Result<Option<String>> {
    if tee == Tee::AwsNitroEnclave && initdata.is_some() {
        anyhow::bail!(
            "--initdata is not supported on AWS Nitro Enclaves: InitData is bound by the \
             attestation-agent started with --initdata-toml; fetch resources through the \
             confidential-data-hub, which attests with that attestation-agent"
        );
    }
    Ok(initdata)
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

    // Native evidence provider
    let evidence_provider = NativeEvidenceProvider::new()?;
    let tee = evidence_provider.get_tee_type().await?;
    let evidence_provider = Box::new(evidence_provider);

    // a kbs_protocol client with evidence_provider
    let mut client_builder = KbsClientBuilder::with_evidence_provider(evidence_provider, &url);

    // Sets TeeKeyAlgorithm to ML-KEM if pqc-experimental feature enabled.
    #[cfg(feature = "pqc-experimental")]
    {
        client_builder =
            client_builder.set_tee_key_algorithm(kbs_protocol::TeeKeyAlgorithm::MlKem768A192Kw);
    }

    // if a certificate is given, use it
    if let Some(cf) = cert_file {
        debug!("Reading certificate from cert_file {}", cf.display());
        let cert = fs::read_to_string(cf)?;
        client_builder = client_builder.add_kbs_cert(&cert)
    }

    match cli.command {
        Commands::GetResource { path, initdata } => {
            if let Some(init) = initdata_to_send(tee, initdata)? {
                client_builder = client_builder.add_initdata(init);
            }
            let mut client = client_builder.build()?;

            let resource = if path.contains("://") {
                ResourceUri::try_from(path.as_str())
                    .map_err(|e| anyhow::anyhow!(e))
                    .context("failed to parse ResourceUri")?
            } else {
                let resource_path = match path.starts_with('/') {
                    false => format!("/{path}"),
                    true => path,
                };
                ResourceUri::new("", &resource_path, Some("resource"), None)?
            };
            let (_token, _key) = client.get_token().await?; // attest first
            let resource_bytes = client.get_resource(resource).await?;

            println!("{}", STANDARD.encode(resource_bytes));
        }
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const INITDATA: &str = "version = \"0.1.0\"\nalgorithm = \"sha256\"\n";

    #[test]
    fn initdata_is_refused_up_front_on_aws_nitro_enclaves() {
        let err = initdata_to_send(Tee::AwsNitroEnclave, Some(INITDATA.into())).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--initdata-toml"), "{msg}");
        assert!(msg.contains("confidential-data-hub"), "{msg}");
    }

    #[test]
    fn nitro_without_initdata_is_allowed() {
        assert_eq!(initdata_to_send(Tee::AwsNitroEnclave, None).unwrap(), None);
    }

    #[test]
    fn initdata_is_sent_unchanged_on_other_tees() {
        for tee in [Tee::Tdx, Tee::Snp, Tee::Sample] {
            assert_eq!(
                initdata_to_send(tee, Some(INITDATA.into()))
                    .unwrap()
                    .as_deref(),
                Some(INITDATA)
            );
        }
    }
}
