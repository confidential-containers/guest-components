// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{env, path::Path};

use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{command, Args, Parser, Subcommand};
use crypto::WrapType;
#[cfg(feature = "aliyun")]
use kms::plugins::aliyun::AliyunKmsClient;
#[cfg(feature = "ehsm")]
use kms::plugins::ehsm::EhsmKmsClient;
use kms::{Encrypter, ProviderSettings};
use rand::Rng;
use secret::secret::{layout::envelope::Envelope, Secret, SecretContent, VERSION};
#[cfg(feature = "ehsm")]
use serde_json::Value;
use tokio::{fs, io::AsyncWriteExt};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "secret")]
#[command(bin_name = "secret")]
#[command(author, version, about, long_about = None)]
enum Cli {
    /// Seal the secret
    Seal(SealArgs),

    /// Unseal the given secret
    Unseal(UnsealArgs),
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

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct UnsealArgs {
    /// path of the file which contains the content to be unsealed
    #[arg(short, long)]
    file_path: String,

    /// path of all credential files used by provider
    #[arg(short, long)]
    key_path: String,
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
    #[cfg(feature = "aliyun")]
    Ali(AliProviderArgs),

    /// Intel eHSM driver to seal the envelope
    #[cfg(feature = "ehsm")]
    Ehsm(EhsmProviderArgs),
}

#[cfg(feature = "aliyun")]
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

#[cfg(feature = "ehsm")]
#[derive(Args)]
struct EhsmProviderArgs {
    /// path of the crendential file
    #[arg(short, long)]
    credential_file_path: String,

    /// endpoint of eHSM service
    #[arg(short, long)]
    endpoint: String,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    match args {
        Cli::Unseal(unseal_args) => {
            let secret_json = fs::read(&unseal_args.file_path)
                .await
                .expect("failed to read sealed secret");
            let secret: Secret = serde_json::from_slice(&secret_json)
                .expect("illegal input sealed secret format (json deserialization failed)");

            match secret.r#type {
                SecretContent::Envelope(ref envelope) => match envelope.provider.as_str() {
                    "aliyun" => env::set_var("ALIYUN_IN_GUEST_KEY_PATH", &unseal_args.key_path),
                    "ehsm" => env::set_var("EHSM_IN_GUEST_KEY_PATH", &unseal_args.key_path),
                    _ => {}
                },
                SecretContent::Vault(_) => todo!(),
            }

            let blob = secret.unseal().await.expect("unseal failed");

            let output_file_name =
                Path::new(&format!("{}.unsealed", &unseal_args.file_path)).to_owned();
            if output_file_name.exists() {
                panic!("{}", format!("{:?} already exists", &output_file_name));
            }
            let mut output_file = fs::File::create(&output_file_name)
                .await
                .expect("failed to create unsealed secret file");

            output_file
                .write_all(&blob)
                .await
                .expect("failed to write unsealed secret");

            println!(
                "unseal success, secret is saved in newly generated file: '{:?}'",
                &output_file_name
            );
        }
        Cli::Seal(seal_args) => {
            let blob = fs::read(seal_args.file_path)
                .await
                .expect("failed to read sealed secret");
            let sc = match &seal_args.r#type {
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
        #[cfg(feature = "aliyun")]
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
        #[cfg(feature = "ehsm")]
        EnvelopeArgs::Ehsm(arg) => {
            let (app_id, api_key) = {
                let cred = fs::read_to_string(&arg.credential_file_path)
                    .await
                    .expect("read credential fail");
                let cred_parsed: Value =
                    serde_json::from_str(&cred).expect("serialize credential fail");
                let app_id = cred_parsed
                    .get("AppId")
                    .expect("get app id value fail")
                    .as_str()
                    .expect("get app id string fail");
                let api_key = cred_parsed
                    .get("ApiKey")
                    .expect("get api key value fail")
                    .as_str()
                    .expect("get api key string fail");
                (app_id.to_owned(), api_key.to_owned())
            };

            let client = EhsmKmsClient::new(&app_id, &api_key, &arg.endpoint)
                .expect("create ehsm client fail");
            let provider_settings = client
                .export_provider_settings()
                .expect("aliyun export provider_settings fail");
            (Box::new(client), provider_settings, "ehsm".into())
        }
        _ => {
            panic!("no kms provider is supported, please rebuild the secret cli tool!")
        }
    }
}
