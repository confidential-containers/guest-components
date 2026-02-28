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

#[derive(ToSchema)]
pub struct VersionInfo {
    /// Version string
    pub version: String,

    /// TEE type (optional)
    pub tee: Option<String>,

    /// Additional TEE types
    pub additional_tees: Vec<String>,

    /// Feature string when launching the API server
    pub feature: String,
}

#[utoipa::path(
    get,
    path = "/info",
    responses(
        (status = 200, description = "success response",
                content_type = "application/json",
                body = VersionInfo,
                example = json!({"version": "v1.0.0", "tee": "tdx", "additional_tees": [], "feature": "resource"})),
        (status = 403, description = "forbid external access"),
        (status = 404, description = "resource not found"),
        (status = 405, description = "only Get method allowed")
    )
)]
fn _version() {}

fn generate_openapi_document() -> std::io::Result<()> {
    #[derive(OpenApi)]
    #[openapi(
    info(
        title = "CoCo RESTful API",
        description = "HTTP based API for CoCo containers to get resource/evidence/token from confidential-data-hub and attestation-agent."),

    servers(
        (url = "http://127.0.0.1:8006", description = "CoCo RESTful API")
     ),

    paths(_token, _evidence, _aael, _resource, _version)
 )]
    struct ApiDoc;
    let mut file = File::create("openapi/api.json")?;
    let json = ApiDoc::openapi().to_pretty_json()?;
    println!("{}", &json);
    file.write_all(json.as_bytes())
}

fn generate_version_file() -> std::io::Result<()> {
    use std::env;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use std::process::Command;

    let _ = ShadowBuilder::builder()
        .build_pattern(BuildPattern::RealTime)
        .build()
        .expect("Build shadow failed.");
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("guest_components_version");
    let mut f = File::create(dest_path).unwrap();

    let git_version = Command::new("git")
        .args(["describe", "--tags", "--dirty", "--always"])
        .output()
        .unwrap()
        .stdout;

    let git_version = String::from_utf8(git_version).unwrap();
    let git_version = git_version.trim_end();

    writeln!(f, "Guest Components Version: {git_version}").unwrap();
    Ok(())
}

fn main() -> std::io::Result<()> {
    generate_openapi_document().expect("Generate RESTful OpenAPI yaml failed.");
    generate_version_file().expect("Generate version file failed.");
    Ok(())
}
