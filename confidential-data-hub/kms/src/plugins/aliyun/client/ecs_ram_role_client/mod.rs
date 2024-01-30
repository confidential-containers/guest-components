// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{
    collections::{BTreeMap, HashMap},
    env,
    fmt::Write,
};

use async_trait::async_trait;
use chrono::Utc;
use log::error;
use rand::{distributions::Alphanumeric, Rng};
use reqwest::{header::HeaderMap, ClientBuilder};
use serde_json::Value;
use tokio::fs;

mod config;
mod credential;

use crate::{Annotations, Getter, ProviderSettings};
use crate::{Error, Result};

use super::super::annotations::*;
use super::ALIYUN_IN_GUEST_DEFAULT_KEY_PATH;
use config::*;
use credential::*;

#[derive(Clone, Debug)]
pub struct EcsRamRoleClient {
    credential: CredentialEcsRamRole,
    config: ConfigEcsRamRole,
    http_client: reqwest::Client,
}

impl EcsRamRoleClient {
    pub fn new(ecs_ram_role_name: &str, region_id: &str) -> Result<Self> {
        let credential = CredentialEcsRamRole::new(ecs_ram_role_name);

        let endpoint = format!("kms.{region_id}.aliyuncs.com");
        let vpc = format!("kms-vpc.{region_id}.aliyuncs.com");
        let config = ConfigEcsRamRole::new(region_id, &endpoint, &vpc);

        let http_client = ClientBuilder::new()
            .use_rustls_tls()
            .build()
            .map_err(|e| Error::AliyunKmsError(format!("build http client failed: {e}")))?;

        Ok(Self {
            credential,
            config,
            http_client,
        })
    }

    /// This new function is used by a in-pod client. The side-effect is to read the
    /// [`ALIYUN_IN_GUEST_DEFAULT_KEY_PATH`] which is the by default path where the credential
    /// to access kms is saved.
    pub async fn from_provider_settings(_provider_settings: &ProviderSettings) -> Result<Self> {
        let key_path = match env::var("ALIYUN_IN_GUEST_DEFAULT_KEY_PATH") {
            Ok(val) => val,
            Err(_) => ALIYUN_IN_GUEST_DEFAULT_KEY_PATH.to_string(),
        };

        let ecs_ram_role_path = format!("{}/ecsRamRole.json", key_path);

        let ecs_ram_role_str = fs::read_to_string(ecs_ram_role_path).await.map_err(|e| {
            Error::AliyunKmsError(format!(
                "read ecs_ram_role with `fs::read_to_string()` failed: {e}"
            ))
        })?;

        let ecs_ram_role_json: serde_json::Value = serde_json::from_str(&ecs_ram_role_str)
            .map_err(|e| {
                Error::AliyunKmsError(format!(
                    "read ecs_ram_role with `serde_json::from_str()` failed: {e}"
                ))
            })?;

        let ecs_ram_role_name =
            if let Some(ecs_ram_role_name_value) = ecs_ram_role_json.get("ecs_ram_role_name") {
                match ecs_ram_role_name_value.as_str() {
                    Some(ecs_ram_role_name) => ecs_ram_role_name,
                    None => {
                        return Err(Error::AliyunKmsError(
                            "ecs ram role name value is not str.".to_string(),
                        ))
                    }
                }
            } else {
                return Err(Error::AliyunKmsError(
                    "ecs ram role name not exist.".to_string(),
                ));
            };

        let region_id = if let Some(region_id_value) = ecs_ram_role_json.get("region_id") {
            match region_id_value.as_str() {
                Some(region_id) => region_id,
                None => {
                    return Err(Error::AliyunKmsError(
                        "region id value is not str.".to_string(),
                    ))
                }
            }
        } else {
            return Err(Error::AliyunKmsError("region id not exist.".to_string()));
        };

        Self::new(ecs_ram_role_name, region_id)
    }

    /// Export the [`ProviderSettings`] of the current client. This function is to be used
    /// in the encryptor side. The [`ProviderSettings`] will be used to initial a client
    /// in the decryptor side.
    pub fn export_provider_settings(&self) -> ProviderSettings {
        serde_json::Map::<String, Value>::new()
    }
}

#[async_trait]
impl Getter for EcsRamRoleClient {
    async fn get_secret(&mut self, name: &str, annotations: &Annotations) -> Result<Vec<u8>> {
        let secret_settings: AliSecretAnnotations =
            serde_json::from_value(Value::Object(annotations.clone())).map_err(|e| {
                Error::AliyunKmsError(format!(
                    "deserialize SecretSettings for get_secret failed: {e}"
                ))
            })?;

        let get_secret_request = HashMap::<String, String>::from_iter([
            ("SecretName".to_string(), name.to_string()),
            (
                "VersionStage".to_string(),
                secret_settings.version_stage.to_string(),
            ),
            (
                "VersionId".to_string(),
                secret_settings.version_id.to_string(),
            ),
            ("FetchExtendedConfig".to_string(), "true".to_string()),
        ]);

        let headers = self.build_headers("GetSecretValue").map_err(|e| {
            Error::AliyunKmsError(format!("build get_secret request http header failed: {e}"))
        })?;
        let params = self
            .build_params("GetSecretValue", get_secret_request)
            .await
            .map_err(|e| {
                Error::AliyunKmsError(format!("build get_secret request http param failed: {e}"))
            })?;

        let res = self
            .do_request(headers, params)
            .await
            .map_err(|e| Error::AliyunKmsError(format!("do request to kms server failed: {e}")))?;

        let res_string: String = String::from_utf8(res).map_err(|e| {
            Error::AliyunKmsError(format!("get_secret response using `from_utf8` failed: {e}"))
        })?;
        let get_secret_response: Value = serde_json::from_str(&res_string).map_err(|e| {
            Error::AliyunKmsError(format!(
                "get_secret response using `serde_json` failed: {e}"
            ))
        })?;
        let secret_data = if let Some(secret_data_str) = get_secret_response["SecretData"].as_str()
        {
            secret_data_str.as_bytes().to_vec()
        } else {
            return Err(Error::AliyunKmsError(
                "get 'SecretData' from get_secret response failed.".to_string(),
            ));
        };

        Ok(secret_data)
    }
}

impl EcsRamRoleClient {
    const API_VERSION: &'static str = "2016-01-20";
    const SDK_TYPE: &'static str = "normal";
    const SDK_CLIENT: &'static str = "python/2.0.0";
    const SIGNATURE_METHOD: &'static str = "HMAC-SHA1";
    const SIGNATURE_VERSION: &'static str = "1.0";
    const CONTENT_TYPE: &'static str = "json";

    fn build_headers(&self, api_name: &str) -> anyhow::Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            Into::<String>::into(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .parse()?,
        );

        headers.insert("x-acs-version", Self::API_VERSION.parse()?);
        headers.insert("x-acs-action", api_name.parse()?);

        headers.insert("x-sdk-invoke-type", Self::SDK_TYPE.parse()?);
        headers.insert("x-sdk-client", Self::SDK_CLIENT.parse()?);

        Ok(headers)
    }

    async fn build_params(
        &self,
        api_name: &str,
        mut params: HashMap<String, String>,
    ) -> anyhow::Result<HashMap<String, String>> {
        params.insert("Version".to_string(), Self::API_VERSION.to_string());
        params.insert("Action".to_string(), api_name.to_string());
        params.insert("Format".to_string(), Self::CONTENT_TYPE.to_string());
        params.insert("RegionId".to_string(), self.config.region_id.to_string());
        let iso8601_date = Utc::now().format("%Y-%m-%dT%H:%M:%S%.fZ").to_string();
        params.insert("Timestamp".to_string(), iso8601_date.to_string());
        params.insert(
            "SignatureMethod".to_string(),
            Self::SIGNATURE_METHOD.to_string(),
        );
        params.insert("SignatureType".to_string(), "".to_string());
        params.insert(
            "SignatureVersion".to_string(),
            Self::SIGNATURE_VERSION.to_string(),
        );
        let bytes: Vec<u8> = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .collect();
        let hex_nonce: String = bytes.iter().fold(String::new(), |mut output, b| {
            let _ = write!(output, "{b:02X}");
            output
        });
        params.insert("SignatureNonce".to_string(), hex_nonce.to_string());

        let (session_ak, session_sk, token) = self
            .credential
            .get_session_credential()
            .await
            .map_err(|e| {
                Error::AliyunKmsError(format!("get_ecs_ram_role_session_credential() failed: {e}"))
            })?;
        params.insert("AccessKeyId".to_string(), session_ak.to_string());
        params.insert("SecurityToken".to_string(), token.to_string());

        let canonicalized_params = params
            .iter()
            .collect::<BTreeMap<_, _>>()
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    self.credential.urlencode_openapi(k),
                    self.credential.urlencode_openapi(v),
                )
            })
            .collect::<Vec<String>>()
            .join("&");
        let urlencoded_canonicalized_params: String =
            self.credential.urlencode_openapi(&canonicalized_params);
        let string_to_sign = format!("POST&%2F&{}", urlencoded_canonicalized_params);
        let string_signed = self.credential.sign(&string_to_sign, &(session_sk + "&"))?;
        params.insert("Signature".to_string(), string_signed.to_string());

        Ok(params)
    }

    async fn do_request(
        &self,
        headers: HeaderMap,
        params: HashMap<String, String>,
    ) -> anyhow::Result<Vec<u8>> {
        let url_params = params
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    self.credential.urlencode_openapi(k),
                    self.credential.urlencode_openapi(v),
                )
            })
            .collect::<Vec<String>>()
            .join("&");
        let server_url = format!("https://{}/?{}", self.config.endpoint, url_params);

        let response = self
            .http_client
            .post(server_url)
            .headers(headers)
            .send()
            .await?;

        if !response.status().is_success() {
            error!("aliyun kms: do request fail!");
            let content = response.text().await?;
            let error_msg: Value = serde_json::from_str(&content)?;
            let error_msg = format!(
                "status code: {}, request id: {}, error code: {}, message: {}",
                error_msg["HttpStatus"],
                error_msg["RequestId"],
                error_msg["Code"],
                error_msg["Message"]
            );
            anyhow::bail!(error_msg);
        }

        let content = response.text().await?;
        Ok(content.into_bytes())
    }
}
