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

#[cfg(all(feature = "getresource", feature = "snapshot-overlayfs",))]
#[rstest::rstest]
#[case("localhost:5000/coco/busybox:v1", "kbs:///default/credential/coco")]
#[tokio::test]
#[cfg_attr(not(feature = "e2e-test"), ignore)]
#[serial]
async fn retrieve_credentials_via_kbs(#[case] image: &str, #[case] kbs_uri: &str) {
    common::assert_root_privilege();

    let temp = common::TempDirs::new();
    std::env::set_var("CC_IMAGE_WORK_DIR", &temp.work_dir.path());

    let mut image_client = ImageClient::default();
    image_client.config.auth = true;
    image_client.config.file_paths.auth_file = kbs_uri.into();

    let aa_parameter = "provider:attestation-agent:cc_kbc::http://127.0.0.1:8080";
    image_client
        .pull_image(image, temp.bundle_dir.path(), &None, &Some(aa_parameter))
        .await
        .expect("failed to download image");
}
