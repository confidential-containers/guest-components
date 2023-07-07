// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use base64::Engine;
use devicemapper::{DevId, DmFlags, DmName, DmOptions, DM};
use serde::{Deserialize, Serialize};
use serde_json;
use std::path::Path;

const SECTOR_SHIFT: u64 = 9;
const HASH_ALGORITHMS: &[&str] = &["sha1", "sha224", "sha256", "sha384", "sha512", "ripemd160"];

#[derive(Debug, Deserialize, Serialize)]
pub struct DmVerityOption {
    /// Hash algorithm for dm-verity.
    pub hashtype: String,
    /// Used block size for the data device.
    pub blocksize: u64,
    /// Used block size for the hash device.
    pub hashsize: u64,
    /// Size of data device used in verification.
    pub blocknum: u64,
    /// Offset of hash area/superblock on hash_device.
    pub offset: u64,
    /// Root hash for device verification or activation.
    pub hash: String,
}

/// Creates a mapping with <name> backed by data_device <source_device_path>
/// and using hash_device for in-kernel verification.
/// It will return the verity block device Path "/dev/mapper/<name>"
/// Notes: the data device and the hash device are the same one.
pub fn create_verity_device(
    verity_option: &DmVerityOption,
    source_device_path: &Path,
) -> Result<String> {
    let dm = DM::new()?;
    let verity_name = DmName::new(&verity_option.hash)?;
    let id = DevId::Name(verity_name);
    let opts = DmOptions::default().set_flags(DmFlags::DM_READONLY);
    let hash_start_block: u64 =
        (verity_option.offset + verity_option.hashsize - 1) / verity_option.hashsize;

    // verity parameters: <version> <data_device> <hash_device> <data_blk_size> <hash_blk_size>
    // <blocks> <hash_start> <algorithm> <root_hash> <salt>
    // version: on-disk hash version
    //     0 is the original format used in the Chromium OS.
    //     1 is the current format that should be used for new devices.
    // data_device: device containing the data the integrity of which needs to be checked.
    //     It may be specified as a path, like /dev/vdX, or a device number, major:minor.
    // hash_device: device that that supplies the hash tree data.
    //     It is specified similarly to the data device path and is the same device in the function of create_verity_device.
    //     The hash_start should be outside of the dm-verity configured device size.
    // data_blk_size: The block size in bytes on a data device.
    // hash_blk_size: The size of a hash block in bytes.
    // blocks: The number of data blocks on the data device.
    // hash_start: offset, in hash_blk_size blocks, from the start of hash_device to the root block of the hash tree.
    // algorithm: The cryptographic hash algorithm used for this device. This should be the name of the algorithm, like "sha256".
    // root_hash: The hexadecimal encoding of the cryptographic hash of the root hash block and the salt.
    // salt: The hexadecimal encoding of the salt value.
    let verity_params = format!(
        "1 {} {} {} {} {} {} {} {} {}",
        source_device_path.display(),
        source_device_path.display(),
        verity_option.blocksize,
        verity_option.hashsize,
        verity_option.blocknum,
        hash_start_block,
        verity_option.hashtype,
        verity_option.hash,
        "-",
    );
    // Mapping table in device mapper: <start_sector> <size> <target_name> <target_params>:
    // <start_sector> is 0
    // <size> is size of device in sectors, and one sector is equal to 512 bytes.
    // <target_name> is name of mapping target, here "verity" for dm-verity
    // <target_params> are parameters for verity target
    let verity_table = vec![(0, verity_option.blocknum, "verity".into(), verity_params)];

    dm.device_create(verity_name, None, opts)?;
    dm.table_load(&id, verity_table.as_slice(), opts)?;
    dm.device_suspend(&id, opts)?;
    Ok(format!("{}{}", "/dev/mapper/", &verity_option.hash))
}

pub fn get_verity_device_name(verity_options: &str) -> Result<String> {
    let parsed_data = decode_verity_options(verity_options)?;
    Ok(parsed_data.hash)
}
pub fn check_verity_options(option: &DmVerityOption) -> Result<()> {
    if !HASH_ALGORITHMS.contains(&option.hashtype.as_str()) {
        bail!("Unsupported hash algorithm: {}", option.hashtype);
    }
    if verity_block_size_ok(option.blocksize) || verity_block_size_ok(option.hashsize) {
        bail!(
            "Unsupported verity block size: data_block_size = {},hash_block_size = {}",
            option.blocksize,
            option.hashsize
        );
    }
    if misaligned_512(option.offset) {
        bail!("Unsupported verity hash offset: {}", option.offset);
    }
    if option.blocknum == 0 || option.offset != option.blocksize * option.blocknum {
        bail!(
            "Offset is not equal to blocksize * blocknum and blocknum can not be set 0: offset = {}, blocknum = {},blocksize*blocknum = {}",
            option.offset,
            option.blocknum,
            option.blocksize * option.blocknum
        );
    }

    Ok(())
}
pub fn decode_verity_options(verity_options: &str) -> Result<DmVerityOption> {
    let decoded = base64::engine::general_purpose::STANDARD.decode(verity_options)?;
    let parsed_data = serde_json::from_slice::<DmVerityOption>(&decoded)?;
    match check_verity_options(&parsed_data) {
        Ok(()) => Ok(parsed_data),
        Err(e) => bail!("check_verity_options error: {}", e),
    }
}

pub fn close_verity_device(verity_device_name: String) -> Result<()> {
    let dm = devicemapper::DM::new()?;
    let name = devicemapper::DmName::new(&verity_device_name)?;
    dm.device_remove(
        &devicemapper::DevId::Name(name),
        devicemapper::DmOptions::default(),
    )?;
    Ok(())
}
fn verity_block_size_ok(block_size: u64) -> bool {
    (block_size) % 512 != 0 || !(512..=(512 * 1024)).contains(&(block_size))
}
fn misaligned_512(offset: u64) -> bool {
    (offset) & ((1 << SECTOR_SHIFT) - 1) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn test_decode_verity_options() {
        let verity_option = DmVerityOption {
            hashtype: "sha256".to_string(),
            blocksize: 512,
            hashsize: 512,
            blocknum: 16384,
            offset: 8388608,
            hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174".to_string(),
        };
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_string(&verity_option).unwrap());
        let decoded = decode_verity_options(&encoded).unwrap_or_else(|err| panic!("{}", err));
        assert_eq!(decoded.hashtype, verity_option.hashtype);
        assert_eq!(decoded.blocksize, verity_option.blocksize);
        assert_eq!(decoded.hashsize, verity_option.hashsize);
        assert_eq!(decoded.blocknum, verity_option.blocknum);
        assert_eq!(decoded.offset, verity_option.offset);
        assert_eq!(decoded.hash, verity_option.hash);
    }

    #[tokio::test]
    async fn test_check_verity_options() {
        let tests = &[
            DmVerityOption {
                hashtype: "md5".to_string(), // "md5" is not a supported hash algorithm
                blocksize: 512,
                hashsize: 512,
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 3000, // Invalid block size, not a power of 2.
                hashsize: 512,
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 0, // Invalid block size, less than 512.
                hashsize: 512,
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 524800, // Invalid block size, greater than 524288.
                hashsize: 512,
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 3000, // Invalid hash block size, not a power of 2.
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 0, // Invalid hash block size, less than 512.
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 524800, // Invalid hash block size, greater than 524288.
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 512,
                blocknum: 0, // Invalid blocknum, it must be greater than 0.
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 512,
                blocknum: 16384,
                offset: 0, // Invalid offset, it must be greater than 0.
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 512,
                blocknum: 16384,
                offset: 8193, // Invalid offset, it must be aligned to 512.
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityOption {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 512,
                blocknum: 16384,
                offset: 8389120, // Invalid offset, it must be equal to blocksize * blocknum.
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
        ];
        for d in tests.iter() {
            let result = check_verity_options(&d);
            assert!(result.is_err());
        }
        let test_data = DmVerityOption {
            hashtype: "sha256".to_string(),
            blocksize: 512,
            hashsize: 512,
            blocknum: 16384,
            offset: 8388608,
            hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174".to_string(),
        };
        let result = check_verity_options(&test_data);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_verity_device() {
        let work_dir = tempfile::tempdir().unwrap();
        let file_name: std::path::PathBuf = work_dir.path().join("test.file");
        let data = vec![0u8; 1048576];
        fs::write(&file_name, &data)
            .unwrap_or_else(|err| panic!("Failed to write to file: {}", err));

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

        let verity_option = DmVerityOption {
            hashtype: "sha256".to_string(),
            blocksize: 512,
            hashsize: 4096,
            blocknum: 1024,
            offset: 524288,
            hash: "fc65e84aa2eb12941aeaa29b000bcf1d9d4a91190bd9b10b5f51de54892952c6".to_string(),
        };
        let verity_device_path = create_verity_device(&verity_option, &loop_device_path)
            .unwrap_or_else(|err| panic!("{}", err));
        assert_eq!(
            verity_device_path,
            "/dev/mapper/fc65e84aa2eb12941aeaa29b000bcf1d9d4a91190bd9b10b5f51de54892952c6"
        );
        assert!(close_verity_device(
            "fc65e84aa2eb12941aeaa29b000bcf1d9d4a91190bd9b10b5f51de54892952c6".to_string()
        )
        .is_ok());
    }
}
