// Copyright (c) 2022 IBM Corp.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::kbc_modules::{KbcCheckInfo, KbcInterface};

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::decode;
use openssl::symm::{decrypt, Cipher};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::process::Command;
use tonic::codegen::http::Uri;
use uuid::Uuid;

use getsecret::key_broker_service_client::KeyBrokerServiceClient;
use getsecret::{OnlineSecretRequest, RequestDetails};

mod getsecret {
    tonic::include_proto!("keybroker");
}

const KEYS_PATH: &str = "/sys/kernel/security/coco/efi_secret/1ee27366-0c87-43a6-af48-28543eaf7cb0";
const SECRET_MODULE_NAME: &str = "efi_secret";
const MODPROBE_PATH: &str = "/usr/sbin/modprobe";
const MOUNT_PATH: &str = "/usr/bin/mount";

type Ciphers = HashMap<String, Cipher>;

#[derive(Deserialize)]
struct Connection {
    client_id: Uuid,
    key: String,
}

#[derive(Deserialize)]
pub struct AnnotationPacket {
    // Key ID to manage multiple keys
    pub kid: String,
    // Encrypted key to unwrap
    pub wrapped_data: String,
    // Initialisation vector
    pub iv: String,
    // Wrap type to specify encryption algorithm and mode
    pub wrap_type: String,
}

struct SecretKernelModule;

impl SecretKernelModule {
    fn new() -> Result<SecretKernelModule> {
        if !Command::new(MODPROBE_PATH)
            .arg(SECRET_MODULE_NAME)
            .status()?
            .success()
        {
            return Err(anyhow!("Failed to load secret module."));
        }
        Ok(SecretKernelModule {})
    }
}
impl Drop for SecretKernelModule {
    fn drop(&mut self) {
        Command::new(MODPROBE_PATH)
            .arg("-r")
            .arg(SECRET_MODULE_NAME)
            .status()
            .expect("Failed to unload secret module.");
    }
}

pub struct OnlineSevKbc {
    // KBS info for compatibility; unused
    kbs_info: HashMap<String, String>,

    // Known ciphers, corresponding to wrap_type
    ciphers: Ciphers,
    kbs_uri: String,
    connection: Result<Connection>,
}

fn get_ciphers() -> Ciphers {
    // The sample KBC uses aes-gcm (Rust implementation). The offline file system KBC uses OpenSSL
    // instead to get access to hardware acceleration on more platforms (e.g. s390x). As opposed
    // to aes-gcm, OpenSSL will only allow GCM when using AEAD. Because authentication is not
    // handled here, AEAD cannot be used, therefore, CTR is used instead.
    [(String::from("aes_256_ctr"), Cipher::aes_256_ctr())]
        .iter()
        .cloned()
        .collect()
}

#[async_trait]
impl KbcInterface for OnlineSevKbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Ok(KbcCheckInfo {
            kbs_info: self.kbs_info.clone(),
        })
    }

    async fn decrypt_payload(&mut self, annotation: &str) -> Result<Vec<u8>> {
        let annotation_packet: AnnotationPacket = serde_json::from_str(annotation)
            .map_err(|e| anyhow!("Failed to parse annotation: {}", e))?;

        let key = self.get_key_from_kbs(annotation_packet.kid).await?;

        let iv = decode(annotation_packet.iv).map_err(|e| anyhow!("Failed to decode IV: {}", e))?;
        let wrapped_data = decode(annotation_packet.wrapped_data)
            .map_err(|e| anyhow!("Failed to decode wrapped key: {}", e))?;
        let wrap_type = annotation_packet.wrap_type;

        let cipher = self
            .ciphers
            .get(&wrap_type)
            .ok_or_else(|| anyhow!("Received unknown wrap type: {}", wrap_type))?;
        // Redact decryption errors to avoid oracles
        decrypt(*cipher, &key, Some(&iv), &wrapped_data).map_err(|_| anyhow!("Failed to decrypt"))
    }
}

impl OnlineSevKbc {
    #[allow(clippy::new_without_default)]
    pub fn new(kbs_uri: String) -> OnlineSevKbc {
        OnlineSevKbc {
            kbs_info: HashMap::new(),
            ciphers: get_ciphers(),
            kbs_uri,
            connection: load_connection(),
        }
    }

    async fn query_kbs(&self, secret_type: String, secret_id: String) -> Result<Vec<u8>> {
        let uri = format!("http://{}", self.kbs_uri).parse::<Uri>()?;

        let channel = tonic::transport::Channel::builder(uri).connect_lazy();
        let mut client = KeyBrokerServiceClient::new(channel);

        let connection = self
            .connection
            .as_ref()
            .map_err(|e| anyhow!("Failed to get injected connection. {}", e))?;
        let guid = Uuid::new_v4().as_hyphenated().to_string();
        let secret_request = RequestDetails {
            guid: guid.clone(),
            format: "binary".to_string(),
            secret_type,
            id: secret_id,
        };

        let request = tonic::Request::new(OnlineSecretRequest {
            client_id: connection.client_id.as_hyphenated().to_string(),
            secret_requests: vec![secret_request],
        });

        let response = client.get_online_secret(request).await?.into_inner();

        let iv_bytes = base64::decode(response.iv)?;
        let payload_bytes = base64::decode(response.payload)?;
        let key_bytes = base64::decode(connection.key.clone())?;

        let nonce = Nonce::from_slice(&iv_bytes);
        let key = Key::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let decrypted_payload = cipher
            .decrypt(nonce, payload_bytes.as_ref())
            .map_err(|e| anyhow!("Failed to decrypt secret payload. {}", e))?;

        let payload_dict: HashMap<String, Vec<u8>> = bincode::deserialize(&decrypted_payload)?;

        Ok(payload_dict
            .get(&guid)
            .ok_or_else(|| anyhow!("Secret UUID not found."))?
            .to_vec())
    }

    async fn get_key_from_kbs(&self, key_id: String) -> Result<Vec<u8>> {
        self.query_kbs("key".to_string(), key_id).await
    }
}

fn load_connection() -> Result<Connection> {
    mount_security_fs()?;
    let _secret_module = SecretKernelModule::new()?;

    let connection_json = fs::read_to_string(KEYS_PATH)?;
    fs::remove_file(KEYS_PATH).expect("Failed to remove secret file.");

    Ok(serde_json::from_str(&connection_json)?)
}

fn mount_security_fs() -> Result<()> {
    if !Command::new(MOUNT_PATH)
        .arg("-t")
        .arg("securityfs")
        .arg("securityfs")
        .arg("/sys/kernel/security")
        .status()?
        .success()
    {
        return Err(anyhow!("Failed to mount security fs"));
    }
    Ok(())
}
