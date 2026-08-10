// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use hyper::body::HttpBody;
use hyper::{Body, Method, Request, Response, StatusCode, header};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::{debug, error, info};

use crate::VERSION;
use crate::client::{
    aa::{
        AA_AAEL_URL, AA_ADDITIONAL_EVIDENCE_URL, AA_EVIDENCE_URL, AA_ROOT, AA_TOKEN_URL, AAClient,
        AaelEvent,
    },
    cdh::{CDH_RESOURCE_URL, CDH_ROOT, CDHClient},
};
use crate::utils::{decode_runtime_data, split_nth_slash};

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
        &self,
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
                        (AA_TOKEN_URL, &Method::GET) => {
                            info!("Get token");
                            match params.get("token_type") {
                                Some(token_type) => match client.get_token(token_type).await {
                                    std::result::Result::Ok(results) => {
                                        return self.octet_stream_response(results);
                                    }
                                    Err(e) => {
                                        error!("Failed to get token: {e:#}");
                                        return self.internal_error(e.to_string());
                                    }
                                },
                                None => return self.bad_request(),
                            }
                        }
                        (AA_EVIDENCE_URL, &Method::GET) => {
                            info!("Get evidence");
                            match params.get("runtime_data") {
                                Some(runtime_data) => {
                                    let runtime_data = match decode_runtime_data(
                                        runtime_data,
                                        params.get("encoding").map(String::as_str),
                                    ) {
                                        std::result::Result::Ok(data) => data,
                                        std::result::Result::Err(_) => return self.bad_request(),
                                    };
                                    match client.get_evidence(&runtime_data).await {
                                        std::result::Result::Ok(results) => {
                                            return self.octet_stream_response(results);
                                        }
                                        Err(e) => {
                                            error!("Failed to get evidence: {e:#}");
                                            return self.internal_error(e.to_string());
                                        }
                                    }
                                }
                                None => return self.bad_request(),
                            }
                        }
                        (AA_ADDITIONAL_EVIDENCE_URL, &Method::GET) => {
                            info!("Get additional evidence");
                            match params.get("runtime_data") {
                                Some(runtime_data) => {
                                    let runtime_data = match decode_runtime_data(
                                        runtime_data,
                                        params.get("encoding").map(String::as_str),
                                    ) {
                                        std::result::Result::Ok(data) => data,
                                        std::result::Result::Err(_) => return self.bad_request(),
                                    };
                                    match client.get_additional_evidence(&runtime_data).await {
                                        std::result::Result::Ok(results) => {
                                            return self.octet_stream_response(results);
                                        }
                                        Err(e) => {
                                            error!("Failed to get additional evidence: {e:#}");
                                            return self.internal_error(e.to_string());
                                        }
                                    }
                                }
                                None => return self.bad_request(),
                            }
                        }
                        (AA_AAEL_URL, &Method::POST) => {
                            info!("Extend AAEL entry");
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
                                Err(e) => {
                                    error!("Failed to parse AAEL entry request: {e:#}");
                                    return self.internal_error(e.to_string());
                                }
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
                                    return self.json_response(message);
                                }
                                Err(e) => {
                                    error!("Failed to extend AAEL entry: {e:#}");
                                    return self.internal_error(e.to_string());
                                }
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
                    if let Some((api, resource_path)) = split_nth_slash(url_path, 2) {
                        info!("Get resource");
                        match api {
                            CDH_RESOURCE_URL => match client.get_resource(resource_path).await {
                                std::result::Result::Ok(results) => {
                                    return self.octet_stream_response(results);
                                }
                                Err(e) => {
                                    error!("Failed to get resource: {e:#}");
                                    return self.internal_error(e.to_string());
                                }
                            },
                            _ => {
                                return self.not_found();
                            }
                        }
                    }

                    return self.not_found();
                }
                _ => return self.not_found(),
            }
        }

        self.not_found()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{body::to_bytes, Method, Request, StatusCode};
    use rstest::rstest;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345)
    }

    fn remote() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345)
    }

    fn router_no_clients() -> Router {
        Router::new(None, None, "resource".to_string())
    }

    async fn body_str(resp: Response<Body>) -> String {
        let bytes = to_bytes(resp.into_body()).await.unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    async fn get_info(router: &Router) -> Response<Body> {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/info")
            .body(Body::empty())
            .unwrap();
        router.route(loopback(), req).await.unwrap()
    }

    #[tokio::test]
    async fn json_response_has_correct_status_and_content_type() {
        let router = router_no_clients();
        let resp = router.json_response(r#"{"ok":true}"#.to_string()).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(body_str(resp).await, r#"{"ok":true}"#);
    }

    #[tokio::test]
    async fn octet_stream_response_has_correct_status_and_content_type() {
        let router = router_no_clients();
        let data: &[u8] = b"binary-data";
        let resp = router.octet_stream_response(data.to_vec()).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        let body_bytes = to_bytes(resp.into_body()).await.unwrap();
        assert_eq!(body_bytes.as_ref(), data);
    }

    #[rstest]
    #[case(
        |r: &Router| r.forbidden(),
        StatusCode::FORBIDDEN,
        "Forbidden"
    )]
    #[case(
        |r: &Router| r.not_allowed(),
        StatusCode::METHOD_NOT_ALLOWED,
        "Method Not Allowed"
    )]
    #[case(
        |r: &Router| r.not_found(),
        StatusCode::NOT_FOUND,
        "URL NOT FOUND"
    )]
    #[case(
        |r: &Router| r.bad_request(),
        StatusCode::BAD_REQUEST,
        "BAD REQUEST"
    )]
    #[case(
        |r: &Router| r.internal_error("something went wrong".to_string()),
        StatusCode::INTERNAL_SERVER_ERROR,
        "something went wrong"
    )]
    #[tokio::test]
    async fn error_response_builder(
        #[case] build: fn(&Router) -> Result<Response<Body>>,
        #[case] expected_status: StatusCode,
        #[case] expected_body: &str,
    ) {
        let router = router_no_clients();
        let resp = build(&router).unwrap();
        assert_eq!(resp.status(), expected_status);
        assert_eq!(body_str(resp).await, expected_body);
    }

    #[rstest]
    #[case(remote(), "/info", StatusCode::FORBIDDEN)]
    #[case(loopback(), "/unknown", StatusCode::NOT_FOUND)]
    #[tokio::test]
    async fn ip_guard(
        #[case] addr: SocketAddr,
        #[case] uri: &str,
        #[case] expected_status: StatusCode,
    ) {
        let router = router_no_clients();
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let resp = router.route(addr, req).await.unwrap();
        assert_eq!(resp.status(), expected_status);
    }

    #[tokio::test]
    async fn info_get_returns_200_json() {
        let router = router_no_clients();
        let resp = get_info(&router).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn info_response_contains_version_and_feature() {
        let router = router_no_clients();
        let val: serde_json::Value =
            serde_json::from_str(&body_str(get_info(&router).await).await).unwrap();
        assert!(val.get("version").is_some(), "version field missing");
        assert_eq!(val["feature"], "resource");
        assert!(val.get("tee").is_none(), "tee should be absent without AA client");
        assert!(
            val.get("additional_tees").is_none(),
            "additional_tees should be absent without AA client"
        );
    }

    #[rstest]
    #[case(Method::POST)]
    #[case(Method::PUT)]
    #[case(Method::DELETE)]
    #[case(Method::PATCH)]
    #[tokio::test]
    async fn info_non_get_returns_405(#[case] method: Method) {
        let router = router_no_clients();
        let req = Request::builder()
            .method(method)
            .uri("/info")
            .body(Body::empty())
            .unwrap();
        let resp = router.route(loopback(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[rstest]
    #[case("/")]
    #[case("/unknown")]
    #[case("/foo/bar")]
    #[tokio::test]
    async fn unknown_root_path_returns_404(#[case] path: &str) {
        let router = router_no_clients();
        let req = Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let resp = router.route(loopback(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[rstest]
    #[case(Method::GET, "/aa/token?token_type=kbs")]
    #[case(Method::GET, "/aa/evidence?runtime_data=aGVsbG8")]
    #[case(Method::GET, "/aa/additional-evidence?runtime_data=aGVsbG8")]
    #[case(Method::GET, "/aa/aael")]
    #[case(Method::POST, "/aa/aael")]
    #[case(Method::GET, "/aa/unknown-route")]
    #[tokio::test]
    async fn aa_endpoint_without_client_returns_404(
        #[case] method: Method,
        #[case] uri: &str,
    ) {
        let router = router_no_clients();
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let resp = router.route(loopback(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_str(resp).await, "Attestation Feature Not Enabled");
    }

    #[rstest]
    #[case("/cdh/resource/default/key/test")]
    #[case("/cdh/resource")]
    #[case("/cdh/unknown/foo/bar")]
    #[tokio::test]
    async fn cdh_endpoint_without_client_returns_404(#[case] uri: &str) {
        let router = router_no_clients();
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let resp = router.route(loopback(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_str(resp).await, "Resource Feature Not Enabled");
    }
}
