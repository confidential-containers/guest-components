// Copyright (c) 2026 NVIDIA Corporation
//
// SPDX-License-Identifier: Apache-2.0

mod conformance;

use conformance::{conformance_images_dir, image_config_for_registry, LocalRegistry};
use std::path::PathBuf;
use tempfile::TempDir;

const REGISTRY_PORT: u16 = 5000;

fn keep_artifacts() -> bool {
    std::env::var("IMAGE_RS_KEEP_TEST_ARTIFACTS").is_ok()
}

struct PulledImage {
    _work_dir: TempDir,
    bundle_dir: TempDir,
}

impl PulledImage {
    fn rootfs(&self) -> PathBuf {
        self.bundle_dir.path().join("rootfs")
    }

    fn cleanup(self) {
        if !keep_artifacts() {
            let _ = nix::mount::umount(&self.rootfs());
        }
    }
}

async fn pull_image_rs(image_ref: &str, registry_url: &str) -> PulledImage {
    let work_dir = tempfile::tempdir().unwrap();
    let bundle_dir = tempfile::tempdir().unwrap();

    let config = image_config_for_registry(work_dir.path().to_path_buf(), registry_url);
    let mut client = image_rs::builder::ClientBuilder::from(config)
        .build()
        .await
        .expect("Failed to build image client");
    client
        .pull_image(image_ref, bundle_dir.path(), &None, &None)
        .await
        .expect("image-rs pull failed");

    PulledImage {
        _work_dir: work_dir,
        bundle_dir,
    }
}

async fn pull_umoci(image_ref: &str) -> PulledImage {
    use tokio::process::Command;

    let work_dir = tempfile::tempdir().unwrap();
    let bundle_dir = tempfile::tempdir().unwrap();
    let oci_layout = work_dir.path().join("oci");

    let output = Command::new("skopeo")
        .args([
            "copy",
            &format!("docker://{}", image_ref),
            &format!("oci:{}:latest", oci_layout.display()),
            "--src-tls-verify=false",
        ])
        .output()
        .await
        .expect("Failed to execute skopeo");
    assert!(
        output.status.success(),
        "skopeo copy failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::new("umoci")
        .args([
            "unpack",
            "--image",
            &format!("{}:latest", oci_layout.display()),
            bundle_dir.path().to_string_lossy().as_ref(),
        ])
        .output()
        .await
        .expect("Failed to execute umoci");
    assert!(
        output.status.success(),
        "umoci unpack failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    PulledImage {
        _work_dir: work_dir,
        bundle_dir,
    }
}

fn compare_rootfs(
    image_name: &str,
    image_rs_rootfs: &std::path::Path,
    umoci_rootfs: &std::path::Path,
) {
    use std::io::Write;
    use std::process::Command;

    let spec_output = Command::new("gomtree")
        .args([
            "-c",
            "-k",
            "size,type,uid,gid,mode,link,time,sha256digest,xattr,xattrs",
            "-p",
        ])
        .arg(umoci_rootfs)
        .output()
        .expect("Failed to execute gomtree");
    assert!(
        spec_output.status.success(),
        "gomtree spec generation failed: {}",
        String::from_utf8_lossy(&spec_output.stderr)
    );

    let mut spec_file = tempfile::NamedTempFile::new().unwrap();
    spec_file.write_all(&spec_output.stdout).unwrap();

    let verify_output = Command::new("gomtree")
        .args(["-f"])
        .arg(spec_file.path())
        .args(["-p"])
        .arg(image_rs_rootfs)
        .output()
        .expect("Failed to execute gomtree verify");

    if !verify_output.status.success() {
        let stderr = String::from_utf8_lossy(&verify_output.stderr);
        let stdout = String::from_utf8_lossy(&verify_output.stdout);
        println!(
            "Rootfs mismatch for {} (image-rs vs umoci):\n{}{}",
            image_name, stdout, stderr
        );
    }
}

#[tokio::test]
#[serial_test::serial]
async fn test_unpack_conformance() {
    assert!(
        nix::unistd::Uid::effective().is_root(),
        "This test requires root privileges"
    );

    let images: Vec<_> = std::fs::read_dir(conformance_images_dir())
        .expect("Failed to read conformance-images directory")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "tar"))
        .collect();

    if images.is_empty() {
        eprintln!("No test images found, skipping");
        return;
    }

    let registry = LocalRegistry::start(REGISTRY_PORT)
        .await
        .expect("Failed to start local registry");

    for tar_path in &images {
        let image_name = tar_path.file_stem().unwrap().to_str().unwrap();
        let image_ref = registry
            .load_image(tar_path)
            .await
            .expect("Failed to load image");

        let image_rs_pulled = pull_image_rs(&image_ref, &registry.url()).await;
        println!(
            "image-rs: {} -> {}",
            image_name,
            image_rs_pulled.rootfs().display()
        );

        let umoci_pulled = pull_umoci(&image_ref).await;
        println!(
            "umoci: {} -> {}",
            image_name,
            umoci_pulled.rootfs().display()
        );

        compare_rootfs(
            image_name,
            &image_rs_pulled.rootfs(),
            &umoci_pulled.rootfs(),
        );

        image_rs_pulled.cleanup();
        umoci_pulled.cleanup();
    }
}
