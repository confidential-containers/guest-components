// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(all(feature = "gen-proto", feature = "keywrap-keyprovider-grpc"))]
    tonic_build::configure()
        .build_server(true)
        .out_dir("src/utils/")
        .compile(&["src/utils/proto/keyprovider.proto"], &["src/utils"])?;
    Ok(())
}
