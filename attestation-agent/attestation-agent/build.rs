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

        // generate an `intro` file that includes the feature information of the build
        fn feature_list(features: Vec<&str>) -> String {
            let enabled_features: Vec<&str> = features
                .into_iter()
                .filter(|&feature| env::var(format!("CARGO_FEATURE_{feature}")).is_ok())
                .collect();

            enabled_features.join(", ")
        }

        let token_plugins = feature_list(vec!["KBS", "COCO_AS"]);
        let attester = feature_list(vec![
            "TDX_ATTESTER",
            "SGX_ATTESTER",
            "AZ_SNP_VTPM_ATTESTER",
            "AZ_TDX_VTPM_ATTESTER",
            "SNP_ATTESTER",
            "SE_ATTESTER",
        ]);

        let out_dir = env::var("OUT_DIR").unwrap();
        let dest_path = Path::new(&out_dir).join("version");
        let mut f = File::create(dest_path).unwrap();

        writeln!(f, "supported attesters: {attester}").unwrap();
        write!(f, "token plugins: {token_plugins}").unwrap();
    }

    let _ = ShadowBuilder::builder()
        .build_pattern(BuildPattern::RealTime)
        .build()
        .unwrap();
    Ok(())
}
