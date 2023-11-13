// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(feature = "ttrpc")]
use ttrpc_codegen::{Codegen, Customize, ProtobufCustomize};

fn main() -> std::io::Result<()> {
    #[cfg(feature = "grpc")]
    {
        tonic_build::configure()
            .build_server(true)
            .protoc_arg("--experimental_allow_proto3_optional")
            .compile(
                &[
                    "../protos/keyprovider.proto",
                    "../protos/getresource.proto",
                    "../protos/attestation-agent.proto",
                ],
                &["../protos"],
            )?;
    }

    #[cfg(feature = "ttrpc")]
    {
        let protos = vec![
            "../protos/keyprovider.proto",
            "../protos/getresource.proto",
            "../protos/attestation-agent.proto",
        ];
        let protobuf_customized = ProtobufCustomize::default().gen_mod_rs(false);

        Codegen::new()
            .out_dir("src/rpc/ttrpc_protocol")
            .inputs(&protos)
            .include("../protos")
            .rust_protobuf()
            .customize(Customize {
                async_all: true,
                ..Default::default()
            })
            .rust_protobuf_customize(protobuf_customized)
            .run()
            .expect("Generate ttrpc protocol code failed.");
    }

    Ok(())
}
