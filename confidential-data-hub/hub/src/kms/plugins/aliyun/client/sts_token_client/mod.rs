// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod credential;

use std::{
    collections::{BTreeMap, HashMap},
    fmt::Write,
};

use anyhow::bail;
use chrono::Utc;
use credential::StsCredential;
use log::error;
use rand::{distr::Alphanumeric, Rng};
use reqwest::{header::HeaderMap, ClientBuilder};
use serde::Deserialize;
use serde_json::Value;
use tokio::fs;

use crate::kms::{
    error::{Error, Result},
    plugins::aliyun::annotations::AliSecretAnnotations,
    Annotations, ProviderSettings,
};

#[derive(Debug, Clone)]
pub struct StsTokenClient {
    ak: String,
    sk: String,
    sts: String,
    endpoint: String,
    region_id: String,
    http_client: reqwest::Client,
}

#[derive(Deserialize)]
pub struct StsSettings {
    token_path: String,
    region_id: String,
}

impl StsTokenClient {
    pub fn from_sts_token(sts: StsCredential, endpoint: String, region_id: String) -> Result<Self> {
        let http_client = ClientBuilder::new()
            .use_rustls_tls()
            .build()
            .map_err(|e| Error::AliyunKmsError(format!("build http client failed: {e:?}")))?;
        Ok(Self {
            ak: sts.ak,
            sk: sts.sk,
            sts: sts.sts,
            endpoint,
            region_id,
            http_client,
        })
    }

    /// Export the [`ProviderSettings`] of the current client. This function is to be used
    /// in the encryptor side. The [`ProviderSettings`] will be used to initial a client
    /// in the decryptor side.
    pub fn export_provider_settings(&self) -> ProviderSettings {
        serde_json::Map::<String, Value>::new()
    }

    /// This new function is used by a in-pod client. The side-effect is to read the
    /// path specified by the provider_setting where the credential to access kms is saved.
    pub async fn from_provider_settings(
        provider_settings: &ProviderSettings,
    ) -> anyhow::Result<Self> {
        let settings: StsSettings =
            serde_json::from_value(Value::Object(provider_settings.to_owned()))?;
        let credential = fs::read_to_string(&settings.token_path).await?;
        let sections: Vec<&str> = credential.split(':').collect();
        if sections.len() != 3 {
            bail!("Unexpected credential format. should be ak:sk:sts");
        }

        let endpoint = format!("kms.{}.aliyuncs.com", settings.region_id);

        let http_client = ClientBuilder::new()
            .use_rustls_tls()
            .build()
            .map_err(|e| Error::AliyunKmsError(format!("build http client failed: {e:?}")))?;

        Ok(Self {
            ak: sections[0].to_string(),
            sk: sections[1].to_string(),
            sts: sections[2].to_string(),
            endpoint,
            region_id: settings.region_id,
            http_client,
        })
    }

    pub async fn get_secret(&self, name: &str, secret_settings: &Annotations) -> Result<Vec<u8>> {
        let secret_settings: AliSecretAnnotations =
            serde_json::from_value(Value::Object(secret_settings.clone())).map_err(|_| {
                Error::AliyunKmsError("illegal Secret annotations format".to_string())
            })?;
        let get_secret_request = HashMap::<String, String>::from_iter([
            ("SecretName".to_string(), name.to_string()),
            ("VersionStage".to_string(), secret_settings.version_stage),
            ("VersionId".to_string(), secret_settings.version_id),
            ("FetchExtendedConfig".to_string(), "true".to_string()),
        ]);

        let headers = self.build_headers("GetSecretValue").map_err(|e| {
            Error::AliyunKmsError(format!(
                "build get_secret request http header failed: {e:?}"
            ))
        })?;

        let params = self
            .build_params("GetSecretValue", get_secret_request)
            .await
            .map_err(|e| {
                Error::AliyunKmsError(format!("build get_secret request http param failed: {e:?}"))
            })?;

        let res = self.do_request(headers, params).await.map_err(|e| {
            Error::AliyunKmsError(format!("do request to kms server failed: {e:?}"))
        })?;

        let res_string: String = String::from_utf8(res).map_err(|e| {
            Error::AliyunKmsError(format!(
                "get_secret response using `from_utf8` failed: {e:?}"
            ))
        })?;
        let get_secret_response: Value = serde_json::from_str(&res_string).map_err(|e| {
            Error::AliyunKmsError(format!(
                "get_secret response using `serde_json` failed: {e:?}"
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
        params.insert("RegionId".to_string(), self.region_id.to_string());
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
        let bytes: Vec<u8> = rand::rng().sample_iter(&Alphanumeric).take(16).collect();
        let hex_nonce: String = bytes.iter().fold(String::new(), |mut output, b| {
            let _ = write!(output, "{b:02X}");
            output
        });
        params.insert("SignatureNonce".to_string(), hex_nonce.to_string());

        params.insert("AccessKeyId".to_string(), self.ak.clone());
        params.insert("SecurityToken".to_string(), self.sts.clone());

        let canonicalized_params = params
            .iter()
            .collect::<BTreeMap<_, _>>()
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    credential::urlencode_openapi(k),
                    credential::urlencode_openapi(v),
                )
            })
            .collect::<Vec<String>>()
            .join("&");
        let urlencoded_canonicalized_params: String =
            credential::urlencode_openapi(&canonicalized_params);
        let string_to_sign = format!("POST&%2F&{}", urlencoded_canonicalized_params);
        let string_signed = credential::sign(&string_to_sign, &(self.sk.clone() + "&"))?;
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
                    credential::urlencode_openapi(k),
                    credential::urlencode_openapi(v),
                )
            })
            .collect::<Vec<String>>()
            .join("&");
        let server_url = format!("https://{}/?{}", self.endpoint, url_params);

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
