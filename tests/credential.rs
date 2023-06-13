// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use image_rs::image::ImageClient;
use rstest::rstest;
use serial_test::serial;

mod common;

#[cfg(feature = "getresource")]
#[rstest]
#[case("liudalibj/private-busy-box", "kbs:///default/credential/test")]
#[case("quay.io/liudalibj/private-busy-box", "kbs:///default/credential/test")]
#[tokio::test]
#[serial]
async fn test_use_credential(#[case] image_ref: &str, #[case] auth_file_uri: &str) {
    common::prepare_test().await;

    // Init AA
    let _aa = common::start_attestation_agent()
        .await
        .expect("Failed to start attestation agent!");

    // AA parameter
    let aa_parameters = common::AA_PARAMETER;

    // clean former test files, which is needed to prevent
    // lint from warning dead code.
    common::clean_configs()
        .await
        .expect("Delete configs failed.");

    let work_dir = tempfile::tempdir().unwrap();
    std::env::set_var("CC_IMAGE_WORK_DIR", &work_dir.path());

    // a new client for every pulling, avoid effection
    // of cache of old client.
    let mut image_client = ImageClient::default();

    // enable container auth
    image_client.config.auth = true;

    // set credential file uri
    image_client.config.file_paths.auth_file = auth_file_uri.into();

    let bundle_dir = tempfile::tempdir().unwrap();

    let res = image_client
        .pull_image(image_ref, bundle_dir.path(), &None, &Some(&aa_parameters))
        .await;
    if cfg!(all(feature = "snapshot-overlayfs",)) {
        assert!(res.is_ok(), "{:?}", res);
        common::umount_bundle(&bundle_dir);
    } else {
        assert!(res.is_err());
    }

    common::clean().await;
}
