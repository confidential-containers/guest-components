// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "aa_ttrpc")]
    {
        use std::fs::File;
        use std::io::{Read, Write};

        fn replace_text_in_file(
            file_name: &str,
            from: &str,
            to: &str,
        ) -> Result<(), std::io::Error> {
            let mut src = File::open(file_name)?;
            let mut contents = String::new();
            src.read_to_string(&mut contents).unwrap();
            drop(src);

            let new_contents = contents.replace(from, to);

            let mut dst = File::create(file_name)?;
            dst.write_all(new_contents.as_bytes())?;

            Ok(())
        }

        ttrpc_codegen::Codegen::new()
            .out_dir("src/token_provider/aa")
            .include("../protos")
            .inputs(["../protos/attestation-agent.proto"])
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
            "src/token_provider/aa/attestation_agent_ttrpc.rs",
            "client: client",
            "client",
        )?;
    }

    Ok(())
}
