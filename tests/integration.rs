// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use image_rs::image::ImageClient;
    use std::path::Path;
    use std::process::{Child, Command};
    use tempfile::TempDir;

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
            .args(&["127.0.0.1:50001"])
            .spawn()?)
    }

    async fn test_pull_signed_image_simple_signing_deny(
        image_client: &mut ImageClient,
        bundle_dir: &TempDir,
    ) {
        let images_cannot_be_pulled = vec![
            // Test cannot pull an unencrypted unsigned image from a protected registry.
            "quay.io/kata-containers/confidential-containers:unsigned",
            // Test unencrypted signed image with unknown signature is rejected.
            "quay.io/kata-containers/confidential-containers:other_signed",
        ];

        for image in images_cannot_be_pulled.iter() {
            assert!(image_client
                .pull_image(
                    image,
                    bundle_dir.path(),
                    &None,
                    &Some("provider:attestation-agent:null_kbc::null")
                )
                .await
                .is_err());
        }
    }

    async fn test_pull_signed_image_simple_signing_allow(
        image_client: &mut ImageClient,
        bundle_dir: &TempDir,
    ) {
        let images_can_be_pulled = vec![
            // Test can pull a unencrypted signed image from a protected registry.
            "quay.io/kata-containers/confidential-containers:signed",
            // Test can pull an unencrypted unsigned image from an unprotected registry.
            "quay.io/prometheus/busybox:latest",
        ];

        for image in images_can_be_pulled.iter() {
            assert!(image_client
                .pull_image(
                    image,
                    bundle_dir.path(),
                    &None,
                    &Some("provider:attestation-agent:null_kbc::null")
                )
                .await
                .is_ok());
        }
    }

    async fn test_pull_signed_image() {
        let work_dir = tempfile::tempdir().unwrap();
        std::env::set_var("CC_IMAGE_WORK_DIR", &work_dir.path());
        let signature_script = format!(
            "scripts/install_test_signatures.sh",
            // std::env::var("CARGO_MANIFEST_DIR").unwrap()
        );

        // let signature_script = "scripts/install_test_signatures.sh";
        Command::new(&signature_script)
            .arg("install")
            .output()
            .unwrap();

        let mut image_client = ImageClient::default();
        image_client.config.security_validate = true;

        let bundle_dir = tempfile::tempdir().unwrap();

        test_pull_signed_image_simple_signing_deny(&mut image_client, &bundle_dir).await;
        test_pull_signed_image_simple_signing_allow(&mut image_client, &bundle_dir).await;

        assert_eq!(image_client.meta_store.lock().await.image_db.len(), 2);

        Command::new(&signature_script)
            .arg("clean")
            .output()
            .unwrap();
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

        test_pull_signed_image().await;
        aa.kill().expect("Failed to stop attestation agent!");
    }
}
