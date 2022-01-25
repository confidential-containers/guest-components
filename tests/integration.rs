// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use image_rs::image::ImageClient;
    use std::path::Path;
    use std::process::{Child, Command};

    fn start_attestation_agent() -> Result<Child> {
        let script_dir = format!("{}/{}", std::env!("CARGO_MANIFEST_DIR"), "scripts");
        let aa_path = format!("{}/{}", script_dir, "attestation-agent");

        if !Path::new(&aa_path).exists() {
            let script_path = format!("{}/{}", script_dir, "build_attestation_agent.sh");
            Command::new(script_path)
                .output()
                .expect("Failed to build attestation-agent");
        }

        Ok(Command::new(aa_path)
            .args(&["--keyprovider_sock"])
            .args(&["127.0.0.1:48888"])
            .spawn()?)
    }

    #[tokio::test]
    async fn test_image_rs() {
        let mut aa = start_attestation_agent().expect("Failed to start attestation agent!");

        let manifest_dir = std::env!("CARGO_MANIFEST_DIR");
        let image = "docker.io/arronwang/busybox_kbs_encrypted";

        let keyprovider_config =
            format!("{}/{}", manifest_dir, "test_data/ocicrypt_keyprovider.conf");
        std::env::set_var("OCICRYPT_KEYPROVIDER_CONFIG", keyprovider_config);
        let decrypt_config = "provider:attestation-agent:sample_kbc::null";

        let work_dir = tempfile::tempdir().unwrap();
        std::env::set_var("CC_IMAGE_WORK_DIR", &work_dir.path());
        let bundle_dir = tempfile::tempdir().unwrap();

        let mut image_client = ImageClient::default();
        assert!(image_client
            .pull_image(image, bundle_dir.path(), &None, &Some(decrypt_config))
            .await
            .is_ok());

        aa.kill().expect("Failed to stop attestation agent!");
    }
}
