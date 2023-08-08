// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{command, Args, Parser, Subcommand};
use crypto::WrapType;
use kms::{plugins::aliyun::AliyunKmsClient, Encrypter, ProviderSettings};
use rand::Rng;
use secret::secret::{layout::envelope::Envelope, Secret, SecretContent, VERSION};
use tokio::fs;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "secret")]
#[command(bin_name = "secret")]
#[command(author, version, about, long_about = None)]
enum Cli {
    /// Seal the secret
    Seal(SealArgs),

    /// Unseal the given secret (TODO)
    Unseal,
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct SealArgs {
    /// path of the file which contains the content to be sealed
    #[arg(short, long)]
    file_path: String,

    /// Type of the Secret, i.e. `vault` or `envelope`
    #[command(subcommand)]
    r#type: TypeArgs,
}

#[derive(Subcommand)]
enum TypeArgs {
    /// Envelope format secret
    Envelope(EnvelopeCommand),

    /// Vault format secret (TODO)
    Vault,
}

#[derive(Args)]
struct EnvelopeCommand {
    #[command(subcommand)]
    command: EnvelopeArgs,

    /// key id used in the KMS
    #[arg(short, long)]
    key_id: String,
}

#[derive(Subcommand)]
enum EnvelopeArgs {
    /// Alibaba KMS driver to seal the envelope
    Ali(AliProviderArgs),
}

#[derive(Args)]
struct AliProviderArgs {
    /// path of the password file
    #[arg(short, long)]
    password_file_path: String,

    /// path of the CA cert of the KMS instance
    #[arg(long)]
    cert_path: String,

    /// id if the kms instance
    #[arg(short, long)]
    kms_instance_id: String,

    /// path of the client key to access the KMS
    #[arg(long)]
    client_key_file_path: String,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    match args {
        Cli::Unseal => {
            // TODO
        }
        Cli::Seal(para) => {
            let blob = fs::read(para.file_path)
                .await
                .expect("failed to read sealed secret");
            let sc = match &para.r#type {
                TypeArgs::Envelope(env) => {
                    let (mut encrypter, provider_settings, provider) =
                        handle_envelope_provider(&env.command).await;
                    let mut iv = [0u8; 12];
                    rand::thread_rng().fill(&mut iv);
                    let mut key = [0u8; 32];
                    rand::thread_rng().fill(&mut key);
                    let encrypted_data = crypto::encrypt(
                        Zeroizing::new(key.to_vec()),
                        blob,
                        iv.to_vec(),
                        WrapType::Aes256Gcm,
                    )
                    .expect("encryption failed");

                    let (encrypted_key, annotations) = encrypter
                        .encrypt(&key, &env.key_id)
                        .await
                        .expect("encrypt the key using kms failed");

                    SecretContent::Envelope(Envelope {
                        key_id: env.key_id.clone(),
                        encrypted_key: STANDARD.encode(encrypted_key),
                        encrypted_data: STANDARD.encode(encrypted_data),
                        wrap_type: WrapType::Aes256Gcm,
                        iv: STANDARD.encode(iv),
                        provider,
                        provider_settings,
                        annotations,
                    })
                }
                TypeArgs::Vault => todo!(),
            };

            let secret = Secret {
                version: VERSION.into(),
                r#type: sc,
            };
            let json = serde_json::to_string(&secret).expect("serialize sealed secret failed");
            println!("{json}");
        }
    }
}

async fn handle_envelope_provider(
    args: &EnvelopeArgs,
) -> (Box<dyn Encrypter>, ProviderSettings, String) {
    match args {
        EnvelopeArgs::Ali(arg) => {
            let client_key = fs::read_to_string(&arg.client_key_file_path)
                .await
                .expect("read client key");
            let password = fs::read_to_string(&arg.password_file_path)
                .await
                .expect("read password");
            let cert_pem = fs::read_to_string(&arg.cert_path)
                .await
                .expect("read kms ca cert");
            let client = AliyunKmsClient::new(
                &client_key[..],
                &arg.kms_instance_id,
                &password[..],
                &cert_pem[..],
            )
            .expect("create aliyun client");
            let provider_settings = client
                .export_provider_settings()
                .expect("aliyun export provider_settings failed");
            (Box::new(client), provider_settings, "aliyun".into())
        }
    }
}
