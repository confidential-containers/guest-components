// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod common;

#[cfg(all(
    feature = "kbs",
    any(feature = "keywrap-ttrpc", feature = "keywrap-grpc")
))]
#[rstest::rstest]
#[case("liudalibj/private-busy-box", "kbs:///default/credential/test")]
#[case("quay.io/liudalibj/private-busy-box", "kbs:///default/credential/test")]
#[tokio::test]
#[serial_test::serial]
async fn test_use_credential(#[case] image_ref: &str, #[case] auth_file_uri: &str) {
    common::prepare_test(common::OFFLINE_FS_KBC_RESOURCES_FILE).await;

    // // Init CDH
    let _cdh = common::start_confidential_data_hub()
        .await
        .expect("Failed to start confidential data hub!");

    let work_dir = tempfile::tempdir().unwrap();

    // a new client for every pulling, avoid effection
    // of cache of old client.
    let mut image_client = image_rs::builder::ClientBuilder::default()
        .authenticated_registry_credentials_uri(auth_file_uri.to_string())
        .work_dir(work_dir.into_path())
        .build()
        .await
        .unwrap();

    let bundle_dir = tempfile::tempdir().unwrap();

    let res = image_client
        .pull_image(
            image_ref,
            bundle_dir.path(),
            &None,
            &Some(common::AA_PARAMETER),
        )
        .await;
    if cfg!(all(feature = "snapshot-overlayfs",)) {
        assert!(res.is_ok(), "{:?}", res);
        common::umount_bundle(&bundle_dir);
    } else {
        assert!(res.is_err());
    }

    common::clean().await;
}
