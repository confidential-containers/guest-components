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
        fn feature_list(always_enabled: Vec<&str>, features: Vec<&str>) -> String {
            let enabled_features: Vec<&str> = always_enabled
                .into_iter()
                .chain(
                    features
                        .into_iter()
                        .filter(|&feature| env::var(format!("CARGO_FEATURE_{feature}")).is_ok()),
                )
                .map(|f| f.strip_suffix("_ATTESTER").unwrap_or(f))
                .collect();

            enabled_features.join(", ")
        }

        let token_plugins = feature_list(vec![], vec!["KBS", "COCO_AS"]);
        let attester = feature_list(
            vec!["SAMPLE_ATTESTER", "SAMPLE_DEVICE_ATTESTER"],
            vec![
                "TDX_ATTESTER",
                "SGX_ATTESTER",
                "AZ_SNP_VTPM_ATTESTER",
                "AZ_TDX_VTPM_ATTESTER",
                "SNP_ATTESTER",
                "SE_ATTESTER",
                "CCA_ATTESTER",
                "CSV_ATTESTER",
                "HYGON_DCU_ATTESTER",
                "TPM_ATTESTER",
                "NVIDIA_ATTESTER",
            ],
        );

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
