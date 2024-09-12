// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

fn main() -> std::io::Result<()> {
    #[cfg(feature = "eaa_kbc")]
    {
        println!("cargo:rustc-link-search=native=/usr/local/lib/rats-tls");
        println!("cargo:rustc-link-lib=dylib=rats_tls");
    }

    #[cfg(feature = "gen-proto")]
    {
        tonic_build::configure()
            .build_server(true)
            .out_dir("src/online_sev_kbc/")
            .compile_protos(&["src/online_sev_kbc/getsecret.proto"], &[""])?;
    }

    Ok(())
}
