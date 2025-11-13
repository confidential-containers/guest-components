// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

fn main() {
    #[cfg(feature = "build")]
    {
        ttrpc_codegen::Codegen::new()
            .out_dir("./src/ttrpc/aa")
            .inputs(["./protos/attestation-agent/attestation-agent.proto"])
            .include("./protos/attestation-agent")
            .rust_protobuf()
            .customize(ttrpc_codegen::Customize {
                async_all: true,
                ..Default::default()
            })
            .rust_protobuf_customize(ttrpc_codegen::ProtobufCustomize::default().gen_mod_rs(false))
            .run()
            .expect("ttrpc proto files build");

        ttrpc_codegen::Codegen::new()
            .out_dir("./src/ttrpc/cdh")
            .inputs([
                "./protos/confidential-data-hub/api.proto",
                "./protos/confidential-data-hub/keyprovider.proto",
            ])
            .include("./protos/confidential-data-hub")
            .rust_protobuf()
            .customize(ttrpc_codegen::Customize {
                async_all: true,
                ..Default::default()
            })
            .rust_protobuf_customize(ttrpc_codegen::ProtobufCustomize::default().gen_mod_rs(false))
            .run()
            .expect("ttrpc proto files build");

        ttrpc_codegen::Codegen::new()
            .out_dir("./src/ttrpc/cdh/sync")
            .inputs(["./protos/confidential-data-hub/keyprovider.proto"])
            .include("./protos/confidential-data-hub")
            .rust_protobuf()
            .customize(ttrpc_codegen::Customize {
                async_all: false,
                ..Default::default()
            })
            .rust_protobuf_customize(ttrpc_codegen::ProtobufCustomize::default().gen_mod_rs(false))
            .run()
            .expect("ttrpc proto files build");

        tonic_prost_build::configure()
            .build_server(true)
            .protoc_arg("--experimental_allow_proto3_optional")
            .out_dir("src/grpc/aa")
            .compile_protos(
                &[
                    "./protos/attestation-agent/online-sev.proto",
                    "./protos/attestation-agent/attestation-agent.proto",
                ],
                &["./protos/attestation-agent"],
            )
            .expect("grpc proto files build");

        tonic_prost_build::configure()
            .build_server(true)
            .protoc_arg("--experimental_allow_proto3_optional")
            .out_dir("src/grpc/cdh")
            .compile_protos(
                &[
                    "./protos/confidential-data-hub/api.proto",
                    "./protos/confidential-data-hub/aliyun.proto",
                    "./protos/confidential-data-hub/keyprovider.proto",
                ],
                &["./protos/confidential-data-hub"],
            )
            .expect("grpc proto files build");
    }
}
