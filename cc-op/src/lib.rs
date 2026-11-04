// Copyright (c) 2026 IBM Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::Cursor;
use std::sync::OnceLock;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use hkdf::Hkdf;
use p256::{
    ecdsa::VerifyingKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    PublicKey as P256PublicKey, SecretKey as P256SecretKey,
};
use sha2::Sha256;

//use p256::pkcs8::der::Encode;
use rmp_serde;
use serde::Deserialize;
use toml;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::Pem;

pub mod hpke;
pub mod processors;

static VERIFYING_KEY: OnceLock<VerifyingKey> = OnceLock::new();
static RECEIVER_PRIVATE_KEY: OnceLock<P256SecretKey> = OnceLock::new();
static RANDOM_BYTES: OnceLock<Vec<u8>> = OnceLock::new();

// Expected cc-op toml format
#[derive(Debug, Deserialize)]
struct Config {
    auth_cert: String,
}

#[derive(Debug, Default, PartialEq)]
struct ArgsConfig {
    payload: Option<String>,
}

// Structures for payload
#[derive(serde::Deserialize)]
struct Header {
    r#type: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Payload {
    r#type: String,
    version: u8,
    namespace: String,
    podname: String,
    containername: String,
    timestamp: u64,
    encapsulatedkey: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum CryptoRunData {
    AttachLogsMode {
        enabled: bool,
        has_sandbox_id: bool,
        in_key: Vec<u8>,
        out_key: Vec<u8>,
    },

    ExecMode {
        args: Vec<String>,
        enabled: bool,
        in_key: Vec<u8>,
        out_key: Vec<u8>,
    },
}

pub fn init_ccop(config_toml_path: &str) -> Result<()> {
    match get_toml_content(config_toml_path) {
        Ok(c) => {
            set_auth_public_key(&c.auth_cert)?;
            Ok(())
        }
        Err(e) => return Err(anyhow::Error::from(e)),
    }
}

pub fn get_ccop_address() -> *const OnceLock<VerifyingKey> {
    &VERIFYING_KEY
}

pub fn set_random_bytes(data: Vec<u8>) -> Result<()> {
    if data.len() < 32 {
        return Err(anyhow::anyhow!("cc-op: random bytes must be at least 32B"));
    }

    RANDOM_BYTES
        .set(data)
        .map_err(|_| anyhow::anyhow!("cc-op: random bytes already initialized"))?;

    Ok(())
}

pub fn get_init_crypto() -> Result<CryptoRunData> {
    let ikm = RANDOM_BYTES
        .get()
        .ok_or_else(|| anyhow::anyhow!("cc-op: random bytes have not initialized"))?;

    let hk = Hkdf::<Sha256>::new(None, ikm);

    let mut in_key = vec![0u8; 32];
    hk.expand(b"ccop attach logs in_key v1", &mut in_key)
        .map_err(|e| anyhow::anyhow!("cc-op: HKDF expand in_key failed: {:?}", e))?;

    let mut out_key = vec![0u8; 32];
    hk.expand(b"ccop attach logs out_key v1", &mut out_key)
        .map_err(|e| anyhow::anyhow!("cc-op: HKDF expand out_key failed: {:?}", e))?;

    Ok(CryptoRunData::AttachLogsMode {
        enabled: is_ccop_set(),
        has_sandbox_id: false,
        in_key,
        out_key,
    })
}

// VERIFYING_KEY is set via initdata
// RECEIVER_PRIVATE_KEY is provisioned by trustee
pub fn is_ccop_set() -> bool {
    VERIFYING_KEY.get().is_some()
    // VERIFYING_KEY.get().is_some() &&  RECEIVER_PRIVATE_KEY.get().is_some()
}

pub fn is_agent_private_key_set() -> bool {
    RECEIVER_PRIVATE_KEY.get().is_some()
}

/// Set the receiver's private key from str
/// This should be called once during initialization
pub fn set_agent_private_key(pem_data: &str) -> Result<()> {
    // Try PKCS#8 format first
    match P256SecretKey::from_pkcs8_pem(&pem_data) {
        Ok(key) => match RECEIVER_PRIVATE_KEY.set(key) {
            Ok(()) => eprintln!("RECEIVER_PRIVATE_KEY stored OK"),
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "cc-op: agent private key is already initialized"
                ));
            }
        },
        Err(_pkcs8_err) => {
            // Try SEC1 format
            match P256SecretKey::from_sec1_pem(&pem_data) {
                Ok(key) => match RECEIVER_PRIVATE_KEY.set(key) {
                    Ok(()) => eprintln!("RECEIVER_PRIVATE_KEY stored OK"),
                    Err(_) => {
                        return Err(anyhow::anyhow!(
                            "cc-op: agent private key is already initialized"
                        ));
                    }
                },
                Err(_sec1_err) => {
                    return Err(anyhow::anyhow!(
                        "cc-op: failed to parse P-256 private key from PEM (tried both PKCS#8 and SEC1 formats)"
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Set the receiver's private key from PEM file content
/// This should be called once during initialization
pub fn set_receiver_private_key_file(filename: &str) -> Result<()> {
    if RECEIVER_PRIVATE_KEY.get().is_some() {
        return Err(anyhow::anyhow!("cc-op: agent private key is already set"));
    }

    let pem_data = std::fs::read_to_string(filename)
        .context(format!("cc-op: failed to read key file {}", filename))?;

    // Try PKCS#8 format first
    let secret_key = if let Ok(key) = P256SecretKey::from_pkcs8_pem(&pem_data) {
        key
    } else if let Ok(key) = P256SecretKey::from_sec1_pem(&pem_data) {
        // Try SEC1 format
        key
    } else {
        return Err(anyhow::anyhow!(
            "cc-op: failed to parse P-256 private key from PEM (tried both PKCS#8 and SEC1 formats)"
        ));
    };

    RECEIVER_PRIVATE_KEY
        .set(secret_key)
        .map_err(|_| anyhow::anyhow!("cc-op: agent private key is already initialized"))?;

    Ok(())
}

pub fn verify_ccop_args(args: Vec<String>) -> Result<CryptoRunData> {
    let cfg = parse_args(&args)?;

    let payload = cfg.payload.unwrap();

    let _ = general_purpose::STANDARD.decode(&payload)?;

    let decoded_args = get_exec_crypto(&payload)?;
    Ok(decoded_args)
}

fn get_exec_crypto(base64str: &str) -> Result<CryptoRunData> {
    if VERIFYING_KEY.get().is_none() {
        return Err(anyhow::anyhow!("cc-op: user auth public key is not set"));
    }

    if RECEIVER_PRIVATE_KEY.get().is_none() {
        return Err(anyhow::anyhow!("cc-op: agent private key is not set"));
    }

    let decoded_bytes = general_purpose::STANDARD.decode(base64str)?;

    let header: Header = rmp_serde::from_slice(&decoded_bytes)?;

    match header.r#type.as_str() {
        "C" => {
            let unpacked_payload: Payload = rmp_serde::from_slice(&decoded_bytes)?;

            let aad = hpke::decrypt::AAD {
                version: unpacked_payload.version,
                name_space: unpacked_payload.namespace,
                pod_name: unpacked_payload.podname,
                container_name: unpacked_payload.containername,
                timestamp: unpacked_payload.timestamp,
            };

            let aad_bytes = hpke::decrypt::encode_aad(&aad);
            let info = b"ccop->agent command v1";
            let receiver_key = RECEIVER_PRIVATE_KEY
                .get()
                .ok_or_else(|| anyhow::anyhow!("cc-op: agent private key is not initialized"))?;

            let sender_verifying_key = VERIFYING_KEY
                .get()
                .ok_or_else(|| anyhow::anyhow!("cc-op: use auth key is not initialized"))?;

            // Convert VerifyingKey to PublicKey
            let sender_public_key = P256PublicKey::from(sender_verifying_key);

            let (plaintext, mut opener) = hpke::decrypt::hpke_auth_decrypt_with_context(
                &receiver_key,
                &sender_public_key,
                &unpacked_payload.encapsulatedkey,
                &unpacked_payload.ciphertext,
                &aad_bytes,
                info,
            )?;
            let args: Vec<String> = rmp_serde::from_slice(&plaintext)?;

            let channel_keys: hpke::decrypt::ChannelKeys =
                hpke::decrypt::derive_channel_keys_from_opener(&mut opener)?;

            let return_data = CryptoRunData::ExecMode {
                enabled: is_ccop_set(),
                args: args.clone(),
                in_key: channel_keys.decrypt_key.to_vec().clone(),
                out_key: channel_keys.encrypt_key.to_vec().clone(),
            };
            Ok(return_data)
        }
        _ => {
            return Err(anyhow::anyhow!("cc-op: unknown type type"));
        }
    }
}

fn get_toml_content(config_toml_path: &str) -> Result<Config> {
    let content = std::fs::read_to_string(&config_toml_path)
        .map_err(|e| anyhow!("cc-op: failed to read {}: {}", &config_toml_path, e))?;
    let config: Config = toml::from_str(&content)
        .map_err(|e| anyhow!("cc-op: failed to parse {}: {}", &config_toml_path, e))?;
    Ok(config)
}

fn parse_args(args: &[String]) -> Result<ArgsConfig> {
    let mut cfg = ArgsConfig::default();
    let mut iter = args.iter().peekable();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--payload" => {
                if let Some(val) = iter.peek() {
                    cfg.payload = Some((*val).clone());
                }
            }
            _ => {} // ignore unknowns
        }
    }

    // Build a detailed error message if anything is missing
    let mut missing = Vec::new();
    if cfg.payload.is_none() {
        missing.push("--payload");
    }

    if !missing.is_empty() {
        Err(anyhow::anyhow!(
            "cc-op error: missing arguments: {}",
            missing.join(", ")
        ))
    } else {
        Ok(cfg)
    }
}

/// This should be called once during initialization
fn set_auth_public_key(pem_public_cert: &str) -> Result<()> {
    // Wrap the byte slice in a Cursor to provide Read + Seek
    if !VERIFYING_KEY.get().is_none() {
        return Err(anyhow::anyhow!(
            "cc-op: user auth public key is already set"
        ));
    }

    let cursor = Cursor::new(pem_public_cert.as_bytes());

    let (pem, _rest) = Pem::read(cursor).context("cc-op: failed to parse PEM")?;

    if pem.label != "CERTIFICATE" {
        return Err(anyhow::anyhow!("cc-op: PEM does not contain a certificate"));
    }

    // Parse X.509 cert from DER bytes
    let (_, cert) =
        //parse_x509_certificate(&pem.contents).map_err(|_| "Failed to parse X509 certificate")?;
        parse_x509_certificate(&pem.contents).context("cc-op: failed to parse X509 certificate")?;

    // Extract the ECDSA public key DER bytes
    let spki_der = cert.tbs_certificate.subject_pki.raw;

    // First decode into an EC PublicKey
    let pubkey = P256PublicKey::from_public_key_der(spki_der)?;

    // Wrap as an ECDSA VerifyingKey
    let verifying_key = VerifyingKey::from(pubkey);

    let result = VERIFYING_KEY.set(verifying_key);
    match result {
        Ok(_) => Ok(()),
        Err(_) => {
            return Err(anyhow::anyhow!(
                "cc-op: user auth public key is already initialized"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_both_missing() {
        let args: Vec<String> = vec![];
        let result = parse_args(&args);
        println!("test_both_missing: {:?}", result);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "cc-op error: missing arguments: --payload"
        );
    }

    #[test]
    fn test_args_present() {
        let args = vec!["--payload".into(), "payload".into()];
        let cfg = parse_args(&args).unwrap();
        println!("test_both_present: {:?}", cfg);
        assert_eq!(
            cfg,
            ArgsConfig {
                payload: Some("payload".into()),
            }
        );
    }
}
