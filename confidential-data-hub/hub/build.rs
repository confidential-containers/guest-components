// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use shadow_rs::{BuildPattern, ShadowBuilder};

fn main() {
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

        let resource_providers = feature_list(vec!["KBS", "SEV"]);
        let kms = feature_list(vec!["ALIYUN", "EHSM"]);

        let out_dir = env::var("OUT_DIR").unwrap();
        let dest_path = Path::new(&out_dir).join("version");
        let mut f = File::create(dest_path).unwrap();

        writeln!(f, "resource providers: {resource_providers}").unwrap();
        write!(f, "kms plugins: {kms}").unwrap();
    }

    let _ = ShadowBuilder::builder()
        .build_pattern(BuildPattern::RealTime)
        .build()
        .unwrap();
}
