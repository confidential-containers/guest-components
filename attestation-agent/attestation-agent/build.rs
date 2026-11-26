// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use shadow_rs::{BuildPattern, ShadowBuilder};

fn main() -> std::io::Result<()> {
    #[cfg(feature = "bin")]
    {
        use std::env;
        use std::fs::File;
        use std::io::Write;
        use std::path::Path;

        let token_plugins = ["KBS", "COCO_AS"]
            .into_iter()
            .filter(|feature| env::var_os(format!("CARGO_FEATURE_{feature}")).is_some())
            .collect::<Vec<_>>()
            .join(", ");
        let out_dir = env::var("OUT_DIR").unwrap();
        let dest_path = Path::new(&out_dir).join("token_plugins");
        let mut f = File::create(dest_path).unwrap();

        write!(f, "token plugins: {token_plugins}").unwrap();
    }

    let _ = ShadowBuilder::builder()
        .build_pattern(BuildPattern::RealTime)
        .build()
        .unwrap();
    Ok(())
}
