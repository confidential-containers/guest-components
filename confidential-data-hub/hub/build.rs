// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

fn main() {
    #[cfg(feature = "grpc")]
    {
        tonic_build::configure()
            .build_server(true)
            .protoc_arg("--experimental_allow_proto3_optional")
            .compile_protos(
                &["./protos/api.proto", "./protos/keyprovider.proto"],
                &["./protos"],
            )
            .expect("Generate grpc protocol code failed.");
    }

    #[cfg(feature = "ttrpc")]
    {
        use std::fs::File;
        use std::io::{Read, Write};
        use ttrpc_codegen::{Codegen, Customize, ProtobufCustomize};

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

        fn replace_text_in_file(file_name: &str, from: &str, to: &str) {
            let mut src = File::open(file_name).unwrap();
            let mut contents = String::new();
            src.read_to_string(&mut contents).unwrap();
            drop(src);

            let new_contents = contents.replace(from, to);

            let mut dst = File::create(file_name).unwrap();
            dst.write_all(new_contents.as_bytes()).unwrap();
        }

        // Fix clippy warnings of code generated from ttrpc_codegen
        replace_text_in_file("src/bin/protos/api_ttrpc.rs", "client: client", "client");
        replace_text_in_file(
            "src/bin/protos/api_ttrpc.rs",
            "#![allow(box_pointers)]\n",
            "",
        );
        replace_text_in_file(
            "src/bin/protos/keyprovider_ttrpc.rs",
            "#![allow(box_pointers)]\n",
            "",
        );
    }

    #[cfg(feature = "bin")]
    {
        use std::env;
        use std::fs::File;
        use std::io::Write;
        use std::path::Path;
        use std::process::Command;

        // generate an `intro` file that includes the feature information of the build
        fn feature_list(features: Vec<&str>) -> String {
            let enabled_features: Vec<&str> = features
                .into_iter()
                .filter(|&feature| env::var(format!("CARGO_FEATURE_{}", feature)).is_ok())
                .collect();

            enabled_features.join(", ")
        }

        let resource_providers = feature_list(vec!["KBS", "SEV"]);
        let kms = feature_list(vec!["ALIYUN", "EHSM"]);

        let out_dir = env::var("OUT_DIR").unwrap();
        let dest_path = Path::new(&out_dir).join("version");
        let mut f = File::create(dest_path).unwrap();

        let git_commit_hash = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout;

        let git_commit_hash = String::from_utf8(git_commit_hash).unwrap();
        let git_commit_hash = git_commit_hash.trim_end();

        let git_status_output = match Command::new("git")
            .args(["diff", "HEAD"])
            .output()
            .unwrap()
            .stdout
            .is_empty()
        {
            true => "",
            false => "(dirty)",
        };

        let socket_type = feature_list(vec!["GRPC", "TTRPC"]);

        writeln!(f, "\n\nCommit Hash: {git_commit_hash} {git_status_output}",).unwrap();
        writeln!(f, "Resource Providers: {}", resource_providers).unwrap();
        writeln!(f, "Socket Type: {}", socket_type).unwrap();

        writeln!(f, "KMS plugins: {}", kms).unwrap();
    }
}
