// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use hyper::body::HttpBody;
use hyper::{header, Body, Method, Request, Response, StatusCode};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::debug;

use crate::client::{
    aa::{AAClient, AaelEvent, AA_AAEL_URL, AA_EVIDENCE_URL, AA_ROOT, AA_TOKEN_URL},
    cdh::{CDHClient, CDH_RESOURCE_URL, CDH_ROOT},
};
use crate::utils::split_nth_slash;
use crate::VERSION;

pub struct Router {
    aa_client: Option<AAClient>,
    cdh_client: Option<CDHClient>,
    version: String,
    feature: String,
}

impl Router {
    pub fn new(
        aa_client: Option<AAClient>,
        cdh_client: Option<CDHClient>,
        feature: String,
    ) -> Self {
        Self {
            aa_client,
            cdh_client,
            version: VERSION.trim_ascii_end().to_string(),
            feature,
        }
    }

    /// Build json response.
    fn json_response(&self, json: String) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json))?)
    }

    /// Build octet-stream response for bytes data.
    fn octet_stream_response(&self, data: Vec<u8>) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(data))?)
    }

    /// Build 400 Bad Request response.
    fn bad_request(&self) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("BAD REQUEST"))?)
    }

    /// Build 403 Forbidden response.
    fn forbidden(&self) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("Forbidden"))?)
    }

    /// Build 404 Not Found response.
    fn not_found(&self) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("URL NOT FOUND"))?)
    }

    /// Build 405 Method Not Allowed response.
    fn not_allowed(&self) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from("Method Not Allowed"))?)
    }

    /// Build 500 Internal Server Error response.
    fn internal_error(&self, body: String) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(body))?)
    }

    pub async fn route(
        &mut self,
        remote_addr: SocketAddr,
        req: Request<Body>,
    ) -> Result<Response<Body>> {
        if !remote_addr.ip().is_loopback() {
            // Return 403 Forbidden response.
            return self.forbidden();
        }

        let path = req.uri().path();
        let method = req.method();
        let params: HashMap<String, String> = req
            .uri()
            .query()
            .map(|v| form_urlencoded::parse(v.as_bytes()).into_owned().collect())
            .unwrap_or_default();
        // First, handle the version request
        if path == "/info" {
            #[derive(Serialize)]
            struct VersionInfo {
                version: String,
                #[serde(skip_serializing_if = "Option::is_none")]
                tee: Option<String>,
                #[serde(skip_serializing_if = "Vec::is_empty")]
                additional_tees: Vec<String>,
                feature: String,
            }

            if method != Method::GET {
                return self.not_allowed();
            }
            let (tee, additional_tees) = match &self.aa_client {
                Some(client) => {
                    let tee = client.get_tee_type().await?;
                    let additional_tees = client.get_additional_tees().await?;
                    (Some(tee), additional_tees)
                }
                None => (None, vec![]),
            };
            let version_info = VersionInfo {
                version: self.version.clone(),
                tee,
                additional_tees,
                feature: self.feature.clone(),
            };
            let version_info = serde_json::to_string(&version_info)?;
            return self.json_response(version_info);
        }

        // Then, handle the other requests
        if let Some((root_path, url_path)) = split_nth_slash(path, 2) {
            debug!("root_path {root_path}, url_path {url_path}");
            match root_path {
                AA_ROOT => {
                    let Some(client) = &self.aa_client else {
                        return Ok(Response::builder()
                            .status(404)
                            .body(Body::from("Attestation Feature Not Enabled"))?);
                    };

                    match (url_path, method) {
                        (AA_TOKEN_URL, &Method::GET) => match params.get("token_type") {
                            Some(token_type) => match client.get_token(token_type).await {
                                std::result::Result::Ok(results) => {
                                    return self.octet_stream_response(results)
                                }
                                Err(e) => return self.internal_error(e.to_string()),
                            },
                            None => return self.bad_request(),
                        },
                        (AA_EVIDENCE_URL, &Method::GET) => match params.get("runtime_data") {
                            Some(runtime_data) => {
                                match client
                                    .get_evidence(&runtime_data.clone().into_bytes())
                                    .await
                                {
                                    std::result::Result::Ok(results) => {
                                        return self.octet_stream_response(results)
                                    }
                                    Err(e) => return self.internal_error(e.to_string()),
                                }
                            }
                            None => return self.bad_request(),
                        },
                        (AA_AAEL_URL, &Method::POST) => {
                            println!("Extend AAEL entry");
                            let aael_entry: AaelEvent = match req
                                .into_body()
                                .collect()
                                .await
                                .map_err(Error::from)
                                .and_then(|data| {
                                    serde_json::from_slice(data.to_bytes().as_ref())
                                        .map_err(|e| anyhow!("Illegal AAEL eventry format: {e}"))
                                }) {
                                std::result::Result::Ok(aael_entry) => aael_entry,
                                Err(e) => return self.internal_error(e.to_string()),
                            };
                            match client
                                .extend_aael_entry(
                                    &aael_entry.domain,
                                    &aael_entry.operation,
                                    &aael_entry.content,
                                )
                                .await
                            {
                                std::result::Result::Ok(message) => {
                                    return self.json_response(message)
                                }
                                Err(e) => return self.internal_error(e.to_string()),
                            }
                        }

                        _ => {
                            return self.not_found();
                        }
                    }
                }

                CDH_ROOT => {
                    let Some(client) = &self.cdh_client else {
                        return Ok(Response::builder()
                            .status(404)
                            .body(Body::from("Resource Feature Not Enabled"))?);
                    };
                    match (url_path, method) {
                        (CDH_RESOURCE_URL, &Method::GET) => {
                            match client.get_resource(url_path).await {
                                std::result::Result::Ok(results) => {
                                    return self.octet_stream_response(results)
                                }
                                Err(e) => return self.internal_error(e.to_string()),
                            }
                        }
                        _ => {
                            return self.not_found();
                        }
                    }
                }
                _ => return self.not_allowed(),
            }
        }

        self.not_found()
    }
}
