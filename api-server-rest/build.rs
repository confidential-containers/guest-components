// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use shadow_rs::{BuildPattern, ShadowBuilder};
use std::fs::File;
use std::io::Write;
use utoipa::{OpenApi, ToSchema};

#[utoipa::path(
    get,
    path = "/aa/token",
    params(
        ("token_type" = String, Query, description = "Token Type")
    ),
    responses(
        (status = 200, description = "success response",
                content_type = "application/octet-stream",
                body = String,
                example = json!({"token": "eyJhbGciOiJFUzI1NiI...", "tee_keypair": "-----BEGIN RSA... "})),
        (status = 400, description = "bad request for invalid token type"),
        (status = 403, description = "forbid external access"),
        (status = 404, description = "resource not found"),
        (status = 405, description = "only Get method allowed")
    )
)]
fn _token() {}

#[utoipa::path(
    get,
    path = "/aa/evidence",
    params(
        ("runtime_data" = String, Query, description = "Runtime Data")
    ),
    responses(
        (status = 200, description = "success response",
                content_type = "application/octet-stream",
                body = String,
                example = json!({"svn":"1","report_data":"eHh4eA=="})),
        (status = 400, description = "bad request for invalid query param"),
        (status = 403, description = "forbid external access"),
        (status = 404, description = "resource not found"),
        (status = 405, description = "only Get method allowed")
    )
)]
fn _evidence() {}

#[derive(ToSchema)]
pub struct AaelEvent {
    /// Attestation Agent Event Log Domain
    pub domain: String,

    /// Attestation Agent Event Log Operation
    pub operation: String,

    /// Attestation Agent Event Log Content
    pub content: String,
}

#[utoipa::path(
    post,
    path = "/aa/aael",
    request_body = AaelEvent,
    responses(
        (status = 200, description = "success response"),
        (status = 400, description = "bad request for invalid body"),
        (status = 403, description = "forbid external access"),
        (status = 405, description = "only POST method allowed")
    )
)]
fn _aael() {}

#[utoipa::path(
    get,
    path = "/cdh/resource/{repository}/{type}/{tag}",
    responses(
        (status = 200, description = "success response",
                content_type = "application/octet-stream",
                body = String,
                example = json!({"123456":"value"})),
        (status = 403, description = "forbid external access"),
        (status = 404, description = "resource not found"),
        (status = 405, description = "only Get method allowed")
    )
)]
fn _resource() {}

fn generate_openapi_document() -> std::io::Result<()> {
    #[derive(OpenApi)]
    #[openapi(
    info(
        title = "CoCo RESTful API",
        description = "HTTP based API for CoCo containers to get resource/evidence/token from confidential-data-hub and attestation-agent."),

    servers(
        (url = "http://127.0.0.1:8006", description = "CoCo RESTful API")
     ),

    paths(_token, _evidence, _aael, _resource)
 )]
    struct ApiDoc;
    let mut file = File::create("openapi/api.json")?;
    let json = ApiDoc::openapi().to_pretty_json()?;
    println!("{}", &json);
    file.write_all(json.as_bytes())
}

fn main() -> std::io::Result<()> {
    generate_openapi_document().expect("Generate RESTful OpenAPI yaml failed.");

    let _ = ShadowBuilder::builder()
        .build_pattern(BuildPattern::RealTime)
        .build()
        .expect("Build shadow failed.");
    Ok(())
}
