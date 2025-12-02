// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod common;

#[cfg(all(
    feature = "kbs",
    any(feature = "keywrap-ttrpc", feature = "keywrap-grpc")
))]
#[rstest::rstest]
#[case::banned_registry("example.com/banned", false)]
#[case::mirror_registry("mirror-test.com/some-image", true)]
#[case::remapping_registry("remapping-test.com/some-image", true)]
#[case::insecure_registry("127.0.0.1:5000/some-image", true)]
#[tokio::test]
#[serial_test::serial]
async fn test_use_registry_configuration(#[case] image_ref: &str, #[case] successful: bool) {
    use testcontainers::{
        core::{IntoContainerPort, WaitFor},
        runners::AsyncRunner,
        ImageExt,
    };
    use tokio::process::Command;

    common::prepare_test(common::OFFLINE_FS_KBC_RESOURCES_FILE).await;

    // // Init CDH
    let _cdh = common::start_confidential_data_hub()
        .await
        .expect("Failed to start confidential data hub!");

    // init registry
    let _registry = testcontainers::GenericImage::new("registry", "2")
        .with_wait_for(WaitFor::message_on_stderr("listening on [::]:5000"))
        .with_mapped_port(5000, 5000.tcp())
        .start()
        .await
        .expect("start registry failed");

    // prepare the image in local registry
    let pull_output = Command::new("docker")
        .args(["pull", "busybox:latest"])
        .output()
        .await
        .expect("Failed to pull BusyBox image");

    assert!(
        pull_output.status.success(),
        "Failed to pull BusyBox image: {pull_output:?}",
    );

    let tag_output = Command::new("docker")
        .args(["tag", "busybox:latest", "127.0.0.1:5000/some-image:latest"])
        .output()
        .await
        .expect("Failed to tag BusyBox image");
    assert!(
        tag_output.status.success(),
        "Failed to tag BusyBox image: {tag_output:?}",
    );

    let push_output = Command::new("docker")
        .args(["push", "127.0.0.1:5000/some-image:latest"])
        .output()
        .await
        .expect("Failed to push BusyBox image to registry");
    assert!(
        push_output.status.success(),
        "Failed to push BusyBox image to registry: {push_output:?}",
    );

    let work_dir = tempfile::tempdir().unwrap();

    // a new client for every pulling, avoid effection
    // of cache of old client.
    let mut image_client = image_rs::builder::ClientBuilder::default()
        .registry_configuration_uri("kbs:///default/registry-configuration/test".into())
        .work_dir(work_dir.path().to_path_buf())
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
    if res.is_ok() {
        common::umount_bundle(&bundle_dir);
    }

    assert_eq!(res.is_ok(), successful, "{res:?}");

    common::clean().await;
}
