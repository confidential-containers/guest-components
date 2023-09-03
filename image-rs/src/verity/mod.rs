// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

pub mod dmverity;
use crate::verity::dmverity::{create_verity_device, destroy_verity_device, DmVerityOption};
use anyhow::Result;
use base64::Engine;
use nix::mount::MsFlags;
use std::path::Path;

/// mount_image_block_with_integrity creates a mapping backed by image block device <source_device_path> and
/// decoding <verity_options> for in-kernel verification. And mount the verity device
/// to <mount_path> with <mount_type>.
/// It will return the verity device path if succeeds and return an error if fails .
pub fn mount_image_block_with_integrity(
    verity_options: &str,
    source_device_path: &Path,
    mount_path: &Path,
    mount_type: &str,
) -> Result<String> {
    let parsed_data = DmVerityOption::try_from(verity_options)?;
    let verity_device_path = create_verity_device(&parsed_data, source_device_path)?;

    nix::mount::mount(
        Some(verity_device_path.as_str()),
        mount_path,
        Some(mount_type),
        MsFlags::MS_RDONLY,
        None::<&str>,
    )?;
    Ok(verity_device_path)
}

/// umount_image_block_with_integrity umounts the filesystem and closes the verity device named verity_device_name.
pub fn umount_image_block_with_integrity(
    mount_path: &Path,
    verity_device_name: String,
) -> Result<()> {
    nix::mount::umount(mount_path)?;
    destroy_dmverity_device(&verity_device_name)?;
    Ok(())
}

pub fn get_image_name_from_remote(image_url: &str) -> Result<String> {
    let image_name = image_url.trim_start_matches("imageurl=");
    let decoded = base64::engine::general_purpose::STANDARD.decode(image_name)?;

    Ok(String::from_utf8_lossy(&decoded).to_string())
}

pub fn destroy_dmverity_device(verity_device_name: &str) -> Result<()> {
    destroy_verity_device(verity_device_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verity::dmverity::get_verity_device_name;
    use base64::Engine;
    use std::fs;
    use std::process::Command;

    #[tokio::test]
    async fn test_mount_and_umount_image_block_with_integrity() {
        const VERITYSETUP_PATH: &[&str] = &["/sbin/veritysetup", "/usr/sbin/veritysetup"];
        //create a disk image file
        let work_dir = tempfile::tempdir().unwrap();
        let mount_dir = tempfile::tempdir().unwrap();
        let file_name: std::path::PathBuf = work_dir.path().join("test.file");
        let default_hash_type = "sha256";
        let default_data_block_size: u64 = 512;
        let default_data_block_num: u64 = 1024;
        let data_device_size = default_data_block_size * default_data_block_num;
        let default_hash_size: u64 = 4096;
        let default_resize_size: u64 = data_device_size * 4;
        let data = vec![0u8; data_device_size as usize];
        fs::write(&file_name, data)
            .unwrap_or_else(|err| panic!("Failed to write to file: {}", err));
        Command::new("mkfs")
            .args(["-t", "ext4", file_name.to_str().unwrap()])
            .output()
            .map_err(|err| format!("Failed to format disk image: {}", err))
            .unwrap_or_else(|err| panic!("{}", err));

        Command::new("truncate")
            .args([
                "-s",
                default_resize_size.to_string().as_str(),
                file_name.to_str().unwrap(),
            ])
            .output()
            .map_err(|err| format!("Failed to resize disk image: {}", err))
            .unwrap_or_else(|err| panic!("{}", err));

        //find an unused loop device and attach the file to the device
        let loop_control = loopdev::LoopControl::open().unwrap_or_else(|err| panic!("{}", err));
        let loop_device = loop_control
            .next_free()
            .unwrap_or_else(|err| panic!("{}", err));
        loop_device
            .with()
            .autoclear(true)
            .attach(file_name.to_str().unwrap())
            .unwrap_or_else(|err| panic!("{}", err));
        let loop_device_path = loop_device
            .path()
            .unwrap_or_else(|| panic!("failed to get loop device path"));
        let loop_device_path_str = loop_device_path
            .to_str()
            .unwrap_or_else(|| panic!("failed to get path string"));

        let mut verity_option = DmVerityOption {
            hashtype: default_hash_type.to_string(),
            blocksize: default_data_block_size,
            hashsize: default_hash_size,
            blocknum: default_data_block_num,
            offset: data_device_size,
            hash: "".to_string(),
        };

        // Calculates and permanently stores hash verification data for data_device.
        let veritysetup_bin = VERITYSETUP_PATH
            .iter()
            .find(|&path| Path::new(path).exists())
            .copied()
            .unwrap_or_else(|| panic!("Veritysetup path not found"));
        let output = Command::new(veritysetup_bin)
            .args([
                "format",
                "--no-superblock",
                "--format=1",
                "-s",
                "",
                &format!("--hash={}", verity_option.hashtype),
                &format!("--data-block-size={}", verity_option.blocksize),
                &format!("--hash-block-size={}", verity_option.hashsize),
                "--data-blocks",
                &format!("{}", verity_option.blocknum),
                "--hash-offset",
                &format!("{}", verity_option.offset),
                loop_device_path_str,
                loop_device_path_str,
            ])
            .output()
            .unwrap_or_else(|err| panic!("{}", err));
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = stdout.lines().collect();
            let hash_strings: Vec<&str> = lines[lines.len() - 1].split_whitespace().collect();
            verity_option.hash = hash_strings[2].to_string()
        } else {
            let error_message = String::from_utf8_lossy(&output.stderr);
            panic!("Failed to create hash device: {}", error_message);
        }

        let serialized_option = serde_json::to_vec(&verity_option)
            .unwrap_or_else(|_| panic!("failed to serialize the options"));
        let encoded_option = base64::engine::general_purpose::STANDARD.encode(serialized_option);
        let res = mount_image_block_with_integrity(
            encoded_option.as_str(),
            &loop_device_path,
            mount_dir.path(),
            "ext4",
        )
        .unwrap_or_else(|err| panic!("Failed to mount image block with integrity {:?}", err));
        assert!(res.contains("/dev/mapper"));
        let verity_device_name = match get_verity_device_name(encoded_option.as_str()) {
            Ok(name) => name,
            Err(err) => {
                panic!("Error getting verity device name: {}", err);
            }
        };
        assert!(umount_image_block_with_integrity(mount_dir.path(), verity_device_name).is_ok());
    }

    #[tokio::test]
    async fn test_get_image_name_from_remote() {
        let image_url = "imageurl=cmVnaXN0cnkuY24taGFuZ3pob3UuYWxpeXVuY3MuY29tL2dvb2dsZV9jb250YWluZXJzL3BhdXNlOjMuNg==";
        let image_name = "registry.cn-hangzhou.aliyuncs.com/google_containers/pause:3.6";
        assert_eq!(get_image_name_from_remote(image_url).unwrap(), image_name);
    }
}
