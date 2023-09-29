// Copyright (c) 2022 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Test for decryption of image layers.

#[cfg(all(feature = "getresource", feature = "encryption"))]
use image_rs::image::ImageClient;
#[cfg(all(feature = "getresource", feature = "encryption"))]
use serial_test::serial;

pub mod common;

/// Ocicrypt-rs config for grpc
#[cfg(all(feature = "getresource", feature = "encryption"))]
#[cfg(not(feature = "keywrap-ttrpc"))]
const OCICRYPT_CONFIG: &str = "test_data/ocicrypt_keyprovider_grpc.conf";

/// Ocicrypt-rs config for ttrpc
#[cfg(all(feature = "getresource", feature = "encryption"))]
#[cfg(feature = "keywrap-ttrpc")]
const OCICRYPT_CONFIG: &str = "test_data/ocicrypt_keyprovider_ttrpc.conf";

#[cfg(all(feature = "getresource", feature = "encryption"))]
#[rstest::rstest]
#[case("ghcr.io/confidential-containers/test-container:unencrypted")]
#[case("ghcr.io/confidential-containers/test-container:encrypted")]
#[tokio::test]
#[serial]
async fn test_decrypt_layers(#[case] image: &str) {
    common::prepare_test(common::AA_OFFLINE_FS_KBC_RESOURCES_FILE).await;
    // Init AA
    let _aa = common::start_attestation_agent()
        .await
        .expect("Failed to start attestation agent!");

    // Set env for ocicrypt-rs. The env is needed by ocicrypt-rs
    // to communicate with AA
    let manifest_dir = std::env!("CARGO_MANIFEST_DIR");
    let keyprovider_config = format!("{}/{}", manifest_dir, OCICRYPT_CONFIG);
    std::env::set_var("OCICRYPT_KEYPROVIDER_CONFIG", keyprovider_config);

    let work_dir = tempfile::tempdir().unwrap();
    std::env::set_var("CC_IMAGE_WORK_DIR", work_dir.path());
    let bundle_dir = tempfile::tempdir().unwrap();

    // clean former test files, which is needed to prevent
    // lint from warning dead code.
    common::clean_configs()
        .await
        .expect("Delete configs failed.");
    let mut image_client = ImageClient::default();
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
