// Copyright (c) 2022 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Test for decryption of image layers.

use image_rs::image::ImageClient;

mod common;

/// The image to be decrypted
const ENCRYPTED_IMAGE_REFERENCE: &str = "docker.io/arronwang/busybox_kbs_encrypted";

/// Ocicrypt-rs config
const OCICRYPT_CONFIG: &str = "test_data/ocicrypt_keyprovider.conf";

/// Parameter `decrypt_config` provided for `ImageClient`.
const AA_PARAMETERS: &str = "provider:attestation-agent:sample_kbc::null";

#[tokio::test]
async fn test_decrypt_layers() {
    // Init AA
    let mut aa = common::start_attestation_agent().expect("Failed to start attestation agent!");

    // Set env for ocicrypt-rs. The env is needed by ocicrypt-rs
    // to communicate with AA
    let manifest_dir = std::env!("CARGO_MANIFEST_DIR");
    let keyprovider_config = format!("{}/{}", manifest_dir, OCICRYPT_CONFIG);
    std::env::set_var("OCICRYPT_KEYPROVIDER_CONFIG", keyprovider_config);

    let work_dir = tempfile::tempdir().unwrap();
    std::env::set_var("CC_IMAGE_WORK_DIR", &work_dir.path());
    let bundle_dir = tempfile::tempdir().unwrap();

    // clean former test files, which is needed to prevent
    // lint from warning dead code.
    common::clean_configs()
        .await
        .expect("Delete configs failed.");

    let mut image_client = ImageClient::default();
    assert!(image_client
        .pull_image(
            ENCRYPTED_IMAGE_REFERENCE,
            bundle_dir.path(),
            &None,
            &Some(AA_PARAMETERS)
        )
        .await
        .is_ok());

    // kill AA when the test is finished
    aa.kill().expect("Failed to stop attestation agent!");
}
