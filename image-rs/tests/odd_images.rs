// Copyright (c) 2026 Confidential Containers Contributors
//
// SPDX-License-Identifier: Apache-2.0
//

//! Regression pulls for historically broken "odd" OCI images.
//!
//! See <https://github.com/confidential-containers/guest-components/issues/1258>
//! and empty-PAX unpack behavior in
//! <https://github.com/confidential-containers/guest-components/issues/1737>.
//!
//! Images are mirrored under
//! `ghcr.io/confidential-containers/test-container-image-rs:odd-*`.

use std::path::Path;
use test_utils::assert_retry;

const ODD_IMAGE_PREFIX: &str = "ghcr.io/confidential-containers/test-container-image-rs";

#[derive(Debug, Clone, Copy)]
enum Expectation {
    /// Pull must succeed; no extra rootfs assertions.
    Ok,
    /// Pull must succeed and this path under rootfs must be absent
    /// (deletion whiteout applied correctly).
    OkPathAbsent(&'static str),
    /// Pull must fail (e.g. empty local PAX rejected by astral-tokio-tar, #1737).
    Err,
}

#[rstest::rstest]
#[case::duplicated_layers("odd-duplicated-layers", Expectation::Ok)]
#[case::whiteout_agnhost("odd-whiteout-agnhost", Expectation::Ok)]
// This one is also cached in ghcr.io/confidential-containers/guest-components/pathological-images/quay_io-curl-curl-8_4_0
#[case::empty_pax("odd-empty-pax", Expectation::Err)]
#[case::whiteout_deletion("odd-whiteout-deletion", Expectation::OkPathAbsent("etc/apache2"))]
#[tokio::test]
#[serial_test::serial]
#[cfg_attr(
    not(target_arch = "x86_64"),
    ignore = "odd-* mirrors are published amd64-first; enable when multi-arch mirrors exist"
)]
async fn test_odd_images(#[case] tag: &str, #[case] expectation: Expectation) {
    assert!(
        nix::unistd::Uid::effective().is_root(),
        "odd-image pull tests require root for overlay snapshot"
    );

    let image = format!("{ODD_IMAGE_PREFIX}:{tag}");
    let work_dir = tempfile::tempdir().unwrap();
    let bundle_dir = tempfile::tempdir().unwrap();

    let mut image_client = image_rs::image::ImageClient::new(work_dir.path().to_path_buf());

    match expectation {
        Expectation::Err => {
            let err = image_client
                .pull_image(&image, bundle_dir.path(), &None, &None)
                .await
                .expect_err("empty-PAX layers must fail unpack (#1737)");
            println!("odd-empty-pax failed as expected: {err}");
        }
        Expectation::Ok | Expectation::OkPathAbsent(_) => {
            assert_retry!(
                5,
                1,
                image_client,
                pull_image,
                &image,
                bundle_dir.path(),
                &None,
                &None
            );

            if let Expectation::OkPathAbsent(rel) = expectation {
                let path = bundle_dir.path().join("rootfs").join(rel);
                assert!(
                    !path.exists(),
                    "expected whiteout to remove {rel}, but {} still exists",
                    path.display()
                );
            }

            umount_rootfs(bundle_dir.path());
        }
    }
}

fn umount_rootfs(bundle_dir: &Path) {
    let rootfs_path = bundle_dir.join("rootfs");
    nix::mount::umount(&rootfs_path).expect("failed to umount rootfs");
}
