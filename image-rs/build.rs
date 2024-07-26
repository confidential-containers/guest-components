// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;

fn main() -> Result<()> {
    #[cfg(feature = "tonic-build")]
    tonic_build::compile_protos("./protos/getresource.proto").context("tonic build")?;

    #[cfg(feature = "tonic-build")]
    tonic_build::configure()
        .build_server(true)
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile(&["./protos/attestation-agent.proto"], &["./protos"])?;

    #[cfg(feature = "ttrpc-codegen")]
    ttrpc_codegen::Codegen::new()
        .out_dir("./src/resource/kbs/ttrpc_proto")
        .input("./protos/getresource.proto")
        .include("./protos")
        .rust_protobuf()
        .customize(ttrpc_codegen::Customize {
            async_all: true,
            ..Default::default()
        })
        .rust_protobuf_customize(ttrpc_codegen::ProtobufCustomize::default().gen_mod_rs(false))
        .run()
        .context("ttrpc build")?;

    #[cfg(feature = "ttrpc-codegen")]
    ttrpc_codegen::Codegen::new()
        .out_dir("./src/runtime_attestation/ttrpc_proto")
        .input("./protos/attestation-agent.proto")
        .include("./protos")
        .rust_protobuf()
        .customize(ttrpc_codegen::Customize {
            async_all: true,
            ..Default::default()
        })
        .rust_protobuf_customize(ttrpc_codegen::ProtobufCustomize::default().gen_mod_rs(false))
        .run()
        .context("ttrpc build")?;

    Ok(())
}
