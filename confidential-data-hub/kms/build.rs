#![allow(missing_docs)]

// extern crate tonic_build;

use anyhow::*;
use std::fs::File;
use std::io::{Read, Write};

fn main() -> Result<()> {
    #[cfg(feature = "aliyun")]
    tonic_build::compile_protos(
        "./src/plugins/aliyun/client/client_key_client/protobuf/dkms_api.proto",
    )?;

    #[cfg(feature = "sev")]
    tonic_build::configure()
        .build_server(true)
        .out_dir("./src/plugins/kbs/sev")
        .compile(&["./src/plugins/kbs/sev/protos/getsecret.proto"], &[""])?;

    ttrpc_codegen::Codegen::new()
        .out_dir("src/attestation/aa_ttrpc")
        .include("../../attestation-agent/protos")
        .inputs(["../../attestation-agent/protos/attestation-agent.proto"])
        .rust_protobuf()
        .customize(ttrpc_codegen::Customize {
            async_all: true,
            ..Default::default()
        })
        .rust_protobuf_customize(ttrpc_codegen::ProtobufCustomize::default().gen_mod_rs(false))
        .run()
        .expect("ttrpc gen async code failed.");

    // Fix clippy warnings of code generated from ttrpc_codegen
    replace_text_in_file(
        "src/attestation/aa_ttrpc/attestation_agent_ttrpc.rs",
        "client: client",
        "client",
    )?;

    Ok(())
}

fn replace_text_in_file(file_name: &str, from: &str, to: &str) -> Result<()> {
    let mut src = File::open(file_name)?;
    let mut contents = String::new();
    src.read_to_string(&mut contents).unwrap();
    drop(src);

    let new_contents = contents.replace(from, to);

    let mut dst = File::create(file_name)?;
    dst.write_all(new_contents.as_bytes())?;

    Ok(())
}
