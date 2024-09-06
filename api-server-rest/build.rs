// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fs::File;
use std::io::Write;
use ttrpc_codegen::{Codegen, Customize, ProtobufCustomize};
use utoipa::OpenApi;

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
        title = "CoCo Restful API",
        description = "HTTP based API for CoCo containers to get resource/evidence/token from confidential-data-hub and attestation-agent."),

    servers(
        (url = "http://127.0.0.1:8006", description = "CoCo Restful API")
     ),

    paths(_token, _evidence, _resource)
 )]
    struct ApiDoc;
    let mut file = File::create("openapi/api.json")?;
    let json = ApiDoc::openapi().to_pretty_json()?;
    println!("{}", &json);
    file.write_all(json.as_bytes())
}

fn main() -> std::io::Result<()> {
    let protos = vec![
        "./protos/confidential_data_hub.proto",
        "./protos/attestation_agent.proto",
    ];
    let protobuf_customized = ProtobufCustomize::default().gen_mod_rs(false);

    use std::fs::File;
    use std::io::{Read, Write};

    fn replace_text_in_file(file_name: &str, from: &str, to: &str) -> Result<(), std::io::Error> {
        let mut src = File::open(file_name)?;
        let mut contents = String::new();
        src.read_to_string(&mut contents).unwrap();
        drop(src);

        let new_contents = contents.replace(from, to);

        let mut dst = File::create(file_name)?;
        dst.write_all(new_contents.as_bytes())?;

        Ok(())
    }

    Codegen::new()
        .out_dir("src/ttrpc_proto")
        .inputs(&protos)
        .include("./protos")
        .rust_protobuf()
        .customize(Customize {
            async_all: true,
            ..Default::default()
        })
        .rust_protobuf_customize(protobuf_customized)
        .run()
        .expect("Generate ttrpc protocol code failed.");

    // Fix clippy warnings of code generated from ttrpc_codegen
    replace_text_in_file(
        "src/ttrpc_proto/attestation_agent_ttrpc.rs",
        "#![allow(box_pointers)]\n",
        "",
    )?;
    replace_text_in_file(
        "src/ttrpc_proto/confidential_data_hub_ttrpc.rs",
        "#![allow(box_pointers)]\n",
        "",
    )?;
    generate_openapi_document().expect("Generate restful OpenAPI yaml failed.");

    Ok(())
}
