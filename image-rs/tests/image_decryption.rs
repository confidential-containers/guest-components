// Copyright (c) 2022 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Test for decryption of image layers.

#[cfg(all(
    feature = "getresource",
    feature = "encryption",
    feature = "keywrap-ttrpc"
))]
use image_rs::image::ImageClient;
#[cfg(all(
    feature = "getresource",
    feature = "encryption",
    feature = "keywrap-ttrpc"
))]
use serial_test::serial;

pub mod common;

// TODO: add `keywrap-grpc` integration test after CDH supports grpc mode
// /// Ocicrypt-rs config for grpc
// #[cfg(all(feature = "getresource", feature = "encryption"))]
// #[cfg(not(feature = "keywrap-ttrpc"))]
// const OCICRYPT_CONFIG: &str = "test_data/ocicrypt_keyprovider_grpc.conf";

/// Ocicrypt-rs config for ttrpc
#[cfg(all(
    feature = "getresource",
    feature = "encryption",
    feature = "keywrap-ttrpc"
))]
const OCICRYPT_CONFIG: &str = "test_data/ocicrypt_keyprovider_ttrpc.conf";

#[cfg(all(
    feature = "getresource",
    feature = "encryption",
    feature = "keywrap-ttrpc"
))]
#[rstest::rstest]
#[case("ghcr.io/confidential-containers/test-container:unencrypted")]
#[case("ghcr.io/confidential-containers/test-container:encrypted")]
#[cfg_attr(not(feature = "nydus"), ignore)]
#[case("ghcr.io/confidential-containers/busybox:nydus-encrypted")]
#[tokio::test]
#[serial]
async fn test_decrypt_layers(#[case] image: &str) {
    common::prepare_test(common::OFFLINE_FS_KBC_RESOURCES_FILE).await;
    // Init CDH
    let _cdh = common::start_confidential_data_hub()
        .await
        .expect("Failed to start confidential data hub!");

    // Set env for ocicrypt-rs. The env is needed by ocicrypt-rs
    // to communicate with CDH
    let manifest_dir = std::env!("CARGO_MANIFEST_DIR");
    let keyprovider_config = format!("{}/{}", manifest_dir, OCICRYPT_CONFIG);
    std::env::set_var("OCICRYPT_KEYPROVIDER_CONFIG", keyprovider_config);

    let work_dir = tempfile::tempdir().unwrap();
    let bundle_dir = tempfile::tempdir().unwrap();

    // clean former test files, which is needed to prevent
    // lint from warning dead code.
    common::clean_configs()
        .await
        .expect("Delete configs failed.");
    let mut image_client = ImageClient::new(work_dir.path().to_path_buf());
    if cfg!(feature = "snapshot-overlayfs") {
        image_client
            .pull_image(image, bundle_dir.path(), &None, &Some(common::AA_PARAMETER))
            .await
            .expect("failed to download image");
        common::umount_bundle(&bundle_dir);
    } else {
        image_client
            .pull_image(image, bundle_dir.path(), &None, &Some(common::AA_PARAMETER))
            .await
            .unwrap_err();
    }

    common::clean().await;
}
