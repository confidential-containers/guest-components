// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

fn main() {
    #[cfg(feature = "bin")]
    {
        use std::fs::File;
        use std::io::{Read, Write};
        use ttrpc_codegen::{Codegen, Customize, ProtobufCustomize};

        fn replace_text_in_file(file_name: &str, from: &str, to: &str) {
            let mut src = File::open(file_name).unwrap();
            let mut contents = String::new();
            src.read_to_string(&mut contents).unwrap();
            drop(src);

            let new_contents = contents.replace(from, to);

            let mut dst = File::create(file_name).unwrap();
            dst.write_all(new_contents.as_bytes()).unwrap();
        }

        let protobuf_customized = ProtobufCustomize::default().gen_mod_rs(false);

        Codegen::new()
            .out_dir("src/bin/protos")
            .inputs(["./protos/api.proto", "./protos/keyprovider.proto"])
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
        replace_text_in_file("src/bin/protos/api_ttrpc.rs", "client: client", "client");
    }
}
