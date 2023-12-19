// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::BTreeMap;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Utc;
use const_format::concatcp;
use log::error;
use prost::Message;
use reqwest::Certificate;
use reqwest::{header::HeaderMap, ClientBuilder};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::fs;

// use crate::plugins::aliyun::client::dkms_api;
use crate::plugins::_IN_GUEST_DEFAULT_KEY_PATH;
use crate::{Annotations, Decrypter, Encrypter, Getter, ProviderSettings};
use crate::{Error, Result};

use super::annotations::{AliCryptAnnotations, AliProviderSettings, AliSecretAnnotations};
use super::credential::Credential;

pub mod dkms_api {
    tonic::include_proto!("dkms_api");
}

pub struct AliyunKmsClient {
    http_client: reqwest::Client,
    credential: Credential,
    kms_instance_id: String,
    endpoint: String,
}

const ALIYUN_IN_GUEST_DEFAULT_KEY_PATH: &str = concatcp!(_IN_GUEST_DEFAULT_KEY_PATH, "/aliyun");

impl AliyunKmsClient {
    fn read_kms_instance_cert(cert_pem: &[u8]) -> Result<Certificate> {
        let kms_instance_ca_cert = Certificate::from_pem(cert_pem)
            .map_err(|e| Error::AliyunKmsError(format!("read kms instance ca cert failed: {e}")))?;
        Ok(kms_instance_ca_cert)
    }

    pub fn new(
        client_key: &str,
        kms_instance_id: &str,
        password: &str,
        cert_pem: &str,
    ) -> Result<Self> {
        let credential = Credential::new(client_key, password).map_err(|e| {
            Error::AliyunKmsError(format!("create credential of the kms instance failed: {e}"))
        })?;
        let endpoint = format!("{kms_instance_id}.cryptoservice.kms.aliyuncs.com");
        let cert = Self::read_kms_instance_cert(cert_pem.as_bytes())?;
        let http_client = ClientBuilder::new()
            .use_rustls_tls()
            .add_root_certificate(cert)
            .build()
            .map_err(|e| Error::AliyunKmsError(format!("build http client failed: {e}")))?;

        Ok(Self {
            http_client,
            kms_instance_id: kms_instance_id.to_string(),
            credential,
            endpoint,
        })
    }

    /// This new function is used by a in-pod client. The side-effect is to read the
    /// [`ALIYUN_IN_GUEST_DEFAULT_KEY_PATH`] which is the by default path where the credential
    /// to access kms is saved.
    pub async fn from_provider_settings(provider_settings: &ProviderSettings) -> Result<Self> {
        let provider_settings: AliProviderSettings =
            serde_json::from_value(Value::Object(provider_settings.clone())).map_err(|e| {
                Error::AliyunKmsError(format!("parse provider setting failed: {e}"))
            })?;

        let cert_path = format!(
            "{ALIYUN_IN_GUEST_DEFAULT_KEY_PATH}/PrivateKmsCA_{}.pem",
            provider_settings.kms_instance_id
        );
        let pswd_path = format!(
            "{ALIYUN_IN_GUEST_DEFAULT_KEY_PATH}/password_{}.json",
            provider_settings.client_key_id
        );
        let client_key_path = format!(
            "{ALIYUN_IN_GUEST_DEFAULT_KEY_PATH}/clientKey_{}.json",
            provider_settings.client_key_id
        );
        let cert_pem = fs::read_to_string(cert_path).await.map_err(|e| {
            Error::AliyunKmsError(format!("read kms instance pem cert failed: {e}"))
        })?;
        let pswd = fs::read_to_string(pswd_path).await.map_err(|e| {
            Error::AliyunKmsError(format!("read password of the credential failed: {e}"))
        })?;
        let client_key = fs::read_to_string(client_key_path).await.map_err(|e| {
            Error::AliyunKmsError(format!("read client key of the credential failed: {e}"))
        })?;

        Self::new(
            &client_key,
            &provider_settings.kms_instance_id,
            &pswd,
            &cert_pem,
        )
    }

    /// Export the [`ProviderSettings`] of the current client. This function is to be used
    /// in the encryptor side. The [`ProviderSettings`] will be used to initial a client
    /// in the decryptor side.
    pub fn export_provider_settings(&self) -> Result<ProviderSettings> {
        let provider_settings = AliProviderSettings {
            client_key_id: self.credential.client_key_id.clone(),
            kms_instance_id: self.kms_instance_id.clone(),
        };

        let provider_settings = serde_json::to_value(provider_settings)
            .map_err(|e| Error::AliyunKmsError(format!("serialize ProviderSettings failed: {e}")))?
            .as_object()
            .expect("must be an object")
            .to_owned();

        Ok(provider_settings)
    }
}

#[async_trait]
impl Encrypter for AliyunKmsClient {
    async fn encrypt(&mut self, data: &[u8], key_id: &str) -> Result<(Vec<u8>, Annotations)> {
        let encrypt_request = dkms_api::EncryptRequest {
            aad: "".into(),
            iv: Vec::new(),
            key_id: key_id.into(),
            algorithm: "AES_GCM".into(),
            padding_mode: "".into(),
            plaintext: data.into(),
        };

        let mut body = Vec::new();
        encrypt_request.encode(&mut body).map_err(|e| {
            Error::AliyunKmsError(format!(
                "encode encrypt request body using protobuf failed: {e}"
            ))
        })?;
        let headers = self.build_headers("Encrypt", &body).map_err(|e| {
            Error::AliyunKmsError(format!("build encrypt request http header failed: {e}"))
        })?;

        let res = self
            .do_request(body, headers)
            .await
            .map_err(|e| Error::AliyunKmsError(format!("do request to kms server failed: {e}")))?;

        let encrypt_response = dkms_api::EncryptResponse::decode(&res[..]).map_err(|e| {
            Error::AliyunKmsError(format!(
                "decrypt encrypt response using protobuf failed: {e}"
            ))
        })?;
        let annotations = AliCryptAnnotations {
            iv: STANDARD.encode(encrypt_response.iv),
        };

        let annotations = serde_json::to_value(annotations)
            .map_err(|e| Error::AliyunKmsError(format!("serialize SecretSettings failed: {e}")))?;
        let annotations = annotations
            .as_object()
            .expect("must be an object")
            .to_owned();
        Ok((encrypt_response.ciphertext_blob, annotations))
    }
}

#[async_trait]
impl Decrypter for AliyunKmsClient {
    async fn decrypt(
        &mut self,
        ciphertext: &[u8],
        key_id: &str,
        annotations: &Annotations,
    ) -> Result<Vec<u8>> {
        let secret_settings: AliCryptAnnotations =
            serde_json::from_value(Value::Object(annotations.clone())).map_err(|e| {
                Error::AliyunKmsError(format!(
                    "deserialize SecretSettings for decryption failed: {e}"
                ))
            })?;

        let iv = STANDARD
            .decode(secret_settings.iv)
            .map_err(|e| Error::AliyunKmsError(format!("decode iv for decryption failed: {e}")))?;
        let decrypt_request = dkms_api::DecryptRequest {
            aad: vec![],
            iv,
            key_id: key_id.into(),
            algorithm: "AES_GCM".into(),
            padding_mode: "".into(),
            ciphertext_blob: ciphertext.to_vec(),
        };
        let mut body = Vec::new();
        decrypt_request.encode(&mut body).map_err(|e| {
            Error::AliyunKmsError(format!("encode decrypt request using protobuf failed: {e}"))
        })?;
        let headers = self.build_headers("Decrypt", &body).map_err(|e| {
            Error::AliyunKmsError(format!("build decrypt request http header failed: {e}"))
        })?;

        let res = self
            .do_request(body, headers)
            .await
            .map_err(|e| Error::AliyunKmsError(format!("do request to kms server failed: {e}")))?;

        let decrypt_response = dkms_api::DecryptResponse::decode(&res[..]).map_err(|e| {
            Error::AliyunKmsError(format!(
                "decode decrypt response using protobuf failed: {e}"
            ))
        })?;
        Ok(decrypt_response.plaintext)
    }
}

#[async_trait]
impl Getter for AliyunKmsClient {
    async fn get_secret(&mut self, name: &str, annotations: &Annotations) -> Result<Vec<u8>> {
        let secret_settings: AliSecretAnnotations =
            serde_json::from_value(Value::Object(annotations.clone())).map_err(|e| {
                Error::AliyunKmsError(format!(
                    "deserialize SecretSettings for get_secret failed: {e}"
                ))
            })?;

        let get_secret_request = dkms_api::GetSecretValueRequest {
            secret_name: name.into(),
            version_stage: secret_settings.version_stage,
            version_id: secret_settings.version_id,
            fetch_extended_config: false,
        };

        let mut body = Vec::new();
        get_secret_request.encode(&mut body).map_err(|e| {
            Error::AliyunKmsError(format!(
                "encode get_secret request body using protobuf failed: {e}"
            ))
        })?;
        let headers = self.build_headers("GetSecretValue", &body).map_err(|e| {
            Error::AliyunKmsError(format!("build get_secret request http header failed: {e}"))
        })?;

        let res = self
            .do_request(body, headers)
            .await
            .map_err(|e| Error::AliyunKmsError(format!("do request to kms server failed: {e}")))?;

        let get_secret_response =
            dkms_api::GetSecretValueResponse::decode(&res[..]).map_err(|e| {
                Error::AliyunKmsError(format!(
                    "decrypt get_secret response using protobuf failed: {e}"
                ))
            })?;
        Ok(get_secret_response.secret_data.into())
    }
}

impl AliyunKmsClient {
    const API_VERSION: &'static str = "dkms-gcs-0.2";
    const SIGNATURE_METHOD: &'static str = "RSA_PKCS1_SHA_256";
    const CONTENT_TYPE: &'static str = "application/x-protobuf";

    fn build_headers(&self, api_name: &str, body: &[u8]) -> anyhow::Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert("Accept", "application/x-protobuf".parse()?);
        headers.insert("Host", self.endpoint.parse()?);
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        headers.insert("date", date.parse()?);
        headers.insert(
            "user-agent",
            Into::<String>::into(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .parse()?,
        );
        headers.insert("x-kms-apiversion", Self::API_VERSION.to_string().parse()?);
        headers.insert("x-kms-apiname", api_name.parse()?);
        headers.insert("x-kms-signaturemethod", Self::SIGNATURE_METHOD.parse()?);
        headers.insert("x-kms-acccesskeyid", self.credential.client_key_id.parse()?);
        headers.insert("Content-Type", "application/x-protobuf".parse()?);
        headers.insert("Content-Length", format!("{}", body.len()).parse()?);
        let sha256 = {
            let mut hasher = Sha256::new();
            hasher.update(body);
            hex::encode_upper(hasher.finalize())
        };
        headers.insert("Content-Sha256", sha256.parse()?);

        let canonicalized_headers = headers
            .iter()
            .filter(|(k, _)| k.as_str().starts_with("x-kms-"))
            .filter_map(|(k, v)| match v.to_str() {
                std::result::Result::Ok(v) => Some((k.as_str(), v.trim())),
                Err(_) => None,
            })
            .collect::<BTreeMap<_, _>>()
            .iter()
            .map(|(k, v)| format!("{k}:{v}\n"))
            .collect::<Vec<String>>()
            .join("");

        let tbs = format!(
            "POST\n{}\n{}\n{}\n{}/",
            sha256,
            Self::CONTENT_TYPE,
            date,
            canonicalized_headers
        );
        let bear_auth = self.credential.generate_bear_auth(&tbs)?;
        headers.insert("Authorization", bear_auth.parse()?);
        Ok(headers)
    }

    async fn do_request(&self, body: Vec<u8>, headers: HeaderMap) -> anyhow::Result<Vec<u8>> {
        let server_url = format!("https://{}", self.endpoint);

        let response = self
            .http_client
            .post(server_url)
            .headers(headers)
            .body(body)
            .send()
            .await?;

        if !response.status().is_success() {
            error!("aliyun kms: do request fail!");
            let body_bytes = response.bytes().await?;
            let error_msg = dkms_api::Error::decode(&*body_bytes)?;
            let error_msg = format!(
                "status code: {}, request id: {}, error code: {}, message: {}",
                error_msg.status_code,
                error_msg.request_id,
                error_msg.error_code,
                error_msg.error_message
            );
            anyhow::bail!(error_msg);
        }

        Ok(response.bytes().await?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::{json, Map, Value};

    use crate::{
        plugins::aliyun::client::AliyunKmsClient, Annotations, Decrypter, Encrypter, Getter,
    };

    #[rstest]
    #[ignore]
    #[case(b"this is a test plaintext")]
    #[ignore]
    #[case(b"this is a another test plaintext")]
    #[tokio::test]
    async fn key_lifetime(#[case] plaintext: &[u8]) {
        let kid = "yyy";
        let provider_settings = json!({
            "client_key_id": "KAAP.f4c8****",
            "kms_instance_id": "kst-shh6****",
        });
        // init encrypter at user side
        let provider_settings = provider_settings.as_object().unwrap().to_owned();
        let mut encryptor = AliyunKmsClient::from_provider_settings(&provider_settings)
            .await
            .unwrap();

        // do encryption
        let (ciphertext, secret_settings) =
            encryptor.encrypt(plaintext, kid).await.expect("encrypt");
        let provider_settings = encryptor.export_provider_settings().unwrap();

        // init decrypter in a guest
        let mut decryptor = AliyunKmsClient::from_provider_settings(&provider_settings)
            .await
            .unwrap();

        // do decryption
        let decrypted = decryptor
            .decrypt(&ciphertext, kid, &secret_settings)
            .await
            .expect("decrypt");

        assert_eq!(decrypted, plaintext);
    }

    #[ignore]
    #[tokio::test]
    async fn get_secret_with_client_key() {
        let secret_name = "test_secret";
        let provider_settings = json!({
            "client_key_id": "KAAP.2bc431c0-416f-4ccb-8638-e71245fd60c1",
            "kms_instance_id": "kst-bjj65794c36xm0v9aeujs",
        });
        // init encrypter at user side
        let provider_settings = provider_settings.as_object().unwrap().to_owned();
        let mut getter = AliyunKmsClient::from_provider_settings(&provider_settings)
            .await
            .unwrap();

        // do get
        let mut annotations: Annotations = Map::<String, Value>::new();
        annotations.insert("version_stage".to_string(), Value::String("".to_string()));
        annotations.insert("version_id".to_string(), Value::String("".to_string()));
        let secret_value = getter
            .get_secret(secret_name, &annotations)
            .await
            .expect("get_secret_with_client_key");

        // We have set "test_secret_value" as secret on Aliyun KMS console.
        assert_eq!(String::from_utf8_lossy(&secret_value), "test_secret_value");
    }
}
