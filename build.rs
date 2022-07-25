// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

fn main() -> shadow_rs::SdResult<()> {
    #[cfg(feature = "eaa_kbc")]
    {
        println!("cargo:rustc-link-search=native=/usr/local/lib/rats-tls");
        println!("cargo:rustc-link-lib=dylib=rats_tls");
    }

    #[cfg(feature = "online_sev_kbc")]
    {
        tonic_build::compile_protos("src/kbc_modules/online_sev_kbc/getsecret.proto")?;
    }

    shadow_rs::new()
}
