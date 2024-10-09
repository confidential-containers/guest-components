// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

fn main() {
    #[cfg(feature = "tonic-build")]
    tonic_build::compile_protos("./protos/getresource.proto").expect("tonic build");

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
        .expect("ttrpc build");
}
