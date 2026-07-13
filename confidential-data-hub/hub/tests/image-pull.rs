// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::time::Duration;

/// Script for preparing resources.json for offline-fs-kbc.
const OFFLINE_FS_KBC_RESOURCE_SCRIPT: &str =
    "../../image-rs/scripts/install_offline_fs_kbc_files.sh";

#[rstest::rstest]
#[case::unsigned_unencrypted_image("busybox:latest")]
#[case::cosign_signed_unencrypted_image(
    "ghcr.io/confidential-containers/test-container-image-rs:cosign-signed"
)]
#[case::unsigned_encrypted_image("ghcr.io/confidential-containers/test-container:encrypted")]
#[case::private_registry("quay.io/liudalibj/private-busy-box")]
#[tokio::test]
#[serial_test::serial]
async fn test_pull_image(#[case] image_ref: &str) {
    tokio::process::Command::new(OFFLINE_FS_KBC_RESOURCE_SCRIPT)
        .arg("install")
        .arg("aa-offline_fs_kbc-resources.json")
        .output()
        .await
        .expect("Install offline-fs-kbcs's resources failed.");

    let tempdir = tempfile::tempdir().unwrap();

    let cdh_path = format!(
        "{}/../../target/debug/ttrpc-cdh",
        std::env!("CARGO_MANIFEST_DIR")
    );

    let keyprovider_config = format!(
        "{}/../../image-rs/test_data/ocicrypt_keyprovider_ttrpc.conf",
        std::env!("CARGO_MANIFEST_DIR")
    );
    let _cdh = tokio::process::Command::new(cdh_path)
        .arg("-c")
        .arg(format!(
            "{}/tests/cdh.toml",
            std::env!("CARGO_MANIFEST_DIR")
        ))
        .env("RUST_LOG", "info")
        .env("OCICRYPT_KEYPROVIDER_CONFIG", keyprovider_config)
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_cmd::cargo::cargo_bin_cmd!("ttrpc-cdh-tool")
        .arg("pull-image")
        .arg("--image-url")
        .arg(image_ref)
        .arg("--bundle-path")
        .arg(tempdir.path())
        .assert()
        .success();

    let mut flag_file = tempdir.path().to_path_buf();
    flag_file.push("rootfs");
    flag_file.push("bin");
    flag_file.push("ls");
    assert!(flag_file.as_path().exists(), "failed to pull image");

    let mounted_path = tempdir.path().to_path_buf().join("rootfs");
    nix::mount::umount(&mounted_path).unwrap();
}
