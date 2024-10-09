// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

fn main() -> std::io::Result<()> {
    #[cfg(feature = "gen-proto")]
    {
        tonic_build::configure()
            .build_server(true)
            .out_dir("src/online_sev_kbc/")
            .compile_protos(&["src/online_sev_kbc/getsecret.proto"], &[""])?;
    }

    Ok(())
}
