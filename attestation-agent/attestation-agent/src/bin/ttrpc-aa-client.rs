// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use base64::Engine;
use clap::{arg, command, Args, Parser, Subcommand};
use const_format::concatcp;
use ttrpc::context;
use ttrpc_dep::ttrpc_protocol::{
    attestation_agent::{
        ExtendRuntimeMeasurementRequest, GetEvidenceRequest, GetTeeTypeRequest, GetTokenRequest,
    },
    attestation_agent_ttrpc::AttestationAgentServiceClient,
};

mod ttrpc_dep;

const TIMEOUT: i64 = 5 * 1000 * 1000 * 1000;

const DEFAULT_UNIX_SOCKET_DIR: &str = "/run/confidential-containers/attestation-agent/";
const UNIX_SOCKET_PREFIX: &str = "unix://";
const DEFAULT_ATTESTATION_SOCKET_ADDR: &str = concatcp!(
    UNIX_SOCKET_PREFIX,
    DEFAULT_UNIX_SOCKET_DIR,
    "attestation-agent.sock"
);

#[derive(Parser)]
#[command(author)]
struct Cli {
    /// Attestation ttRPC Unix socket addr.
    ///
    /// This Unix socket address which the Attestation ttRPC service
    /// will listen to, for example:
    ///
    /// `--attestation_sock unix:///tmp/attestation`
    #[arg(default_value_t = DEFAULT_ATTESTATION_SOCKET_ADDR.to_string(), short, long = "attestation_sock")]
    attestation_sock: String,

    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand)]
#[command(author, version, about, long_about = None)]
enum Operation {
    /// Get the tee type
    GetTee,

    /// Get evidence
    GetEvidence(GetEvidenceArgs),

    /// Get attestation token
    GetToken(GetTokenArgs),

    /// Extend runtime measurement
    ExtendRuntimeMeasurement(ExtendRuntimeMeasurementArgs),
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct GetEvidenceArgs {
    /// base64 encodede runtime data
    #[arg(short, long)]
    runtime_data: String,
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct GetTokenArgs {
    /// token type
    #[arg(short, long)]
    token_type: String,
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct ExtendRuntimeMeasurementArgs {
    /// domain name
    #[arg(short, long)]
    domain: String,

    /// operation name
    #[arg(short, long)]
    operation: String,

    /// content name
    #[arg(short, long)]
    content: String,

    /// PCR index
    #[arg(short, long)]
    pcr: Option<u64>,
}

#[tokio::main]
pub async fn main() {
    let args = Cli::parse();
    let inner =
        ttrpc::asynchronous::Client::connect(&args.attestation_sock).expect("connect ttrpc socket");
    let client = AttestationAgentServiceClient::new(inner);
    match args.operation {
        Operation::GetTee => {
            let req = GetTeeTypeRequest {
                ..Default::default()
            };
            let res = client
                .get_tee_type(context::with_timeout(TIMEOUT), &req)
                .await
                .expect("request to AA");
            println!("{}", res.tee);
        }
        Operation::GetEvidence(args) => {
            let runtime_data = base64::engine::general_purpose::STANDARD
                .decode(args.runtime_data)
                .unwrap();
            let req = GetEvidenceRequest {
                RuntimeData: runtime_data,
                ..Default::default()
            };
            let res = client
                .get_evidence(context::with_timeout(TIMEOUT), &req)
                .await
                .expect("request to AA");
            let evidence = String::from_utf8(res.Evidence).unwrap();
            println!("{evidence}");
        }
        Operation::GetToken(get_token_args) => {
            let req = GetTokenRequest {
                TokenType: get_token_args.token_type,
                ..Default::default()
            };
            let res = client
                .get_token(context::with_timeout(TIMEOUT), &req)
                .await
                .expect("request to AA");
            let token = String::from_utf8(res.Token).unwrap();
            println!("{token}");
        }
        Operation::ExtendRuntimeMeasurement(extend_runtime_measurement_args) => {
            let req = ExtendRuntimeMeasurementRequest {
                Domain: extend_runtime_measurement_args.domain,
                Operation: extend_runtime_measurement_args.operation,
                Content: extend_runtime_measurement_args.content,
                RegisterIndex: extend_runtime_measurement_args.pcr,
                ..Default::default()
            };

            client
                .extend_runtime_measurement(context::with_timeout(TIMEOUT), &req)
                .await
                .expect("request to AA");
            println!("Extended.");
        }
    }
}
