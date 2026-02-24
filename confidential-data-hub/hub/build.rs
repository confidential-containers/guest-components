// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

fn main() {
    #[cfg(feature = "bin")]
    {
        use std::env;
        use std::fs::File;
        use std::io::Write;
        use std::path::Path;
        use std::process::Command;

        use shadow_rs::{BuildPattern, ShadowBuilder};

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
        writeln!(f, "Resource Providers: {resource_providers}").unwrap();
        writeln!(f, "Socket Type: {socket_type}").unwrap();

        writeln!(f, "KMS plugins: {kms}").unwrap();
        let _ = ShadowBuilder::builder()
            .build_pattern(BuildPattern::RealTime)
            .build()
            .unwrap();
    }
}
