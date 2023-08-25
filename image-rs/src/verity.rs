// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Error, Result};
use base64::Engine;
use devicemapper::{DevId, DmFlags, DmName, DmOptions, DM};
use serde::{Deserialize, Serialize};
use serde_json;
use std::path::Path;

/// Configuration information for DmVerity device.
#[derive(Debug, Deserialize, Serialize)]
pub struct DmVerityInfo {
    /// Hash algorithm for dm-verity.
    pub hashtype: String,
    /// Root hash for device verification or activation.
    pub hash: String,
    /// Size of data device used in verification.
    pub blocknum: u64,
    /// Used block size for the data device.
    pub blocksize: u64,
    /// Used block size for the hash device.
    pub hashsize: u64,
    /// Offset of hash area/superblock on hash_device.
    pub offset: u64,
}

impl DmVerityInfo {
    /// Validate configuration information for DmVerity device.
    pub fn validate(&self) -> Result<()> {
        match self.hashtype.to_lowercase().as_str() {
            "sha256" => {
                if self.hash.len() != 64 || hex::decode(&self.hash).is_err() {
                    bail!(
                        "Invalid hash value sha256:{} for DmVerity device with sha256",
                        self.hash,
                    );
                }
            }
            "sha1" => {
                if self.hash.len() != 40 || hex::decode(&self.hash).is_err() {
                    bail!(
                        "Invalid hash value sha1:{} for DmVerity device with sha1",
                        self.hash,
                    );
                }
            }
            // TODO: support ["sha224", "sha384", "sha512", "ripemd160"];
            _ => {
                bail!(
                    "Unsupported hash algorithm {} for DmVerity device {}",
                    self.hashtype,
                    self.hash,
                );
            }
        }

        if self.blocknum == 0 || self.blocknum > u32::MAX as u64 {
            bail!("Zero block count for DmVerity device {}", self.hash);
        }
        if !Self::is_valid_block_size(self.blocksize) || !Self::is_valid_block_size(self.hashsize) {
            bail!(
                "Unsupported verity block size: data_block_size = {},hash_block_size = {}",
                self.blocksize,
                self.hashsize
            );
        }
        if self.offset % self.hashsize != 0 || self.offset < self.blocksize * self.blocknum {
            bail!(
                "Invalid hashvalue offset {} for DmVerity device {}",
                self.offset,
                self.hash
            );
        }

        Ok(())
    }

    fn is_valid_block_size(block_size: u64) -> bool {
        for order in 9..20 {
            if block_size == 1 << order {
                return true;
            }
        }
        false
    }
    fn parse_tarfs_options(source_option: &str) -> std::result::Result<DmVerityInfo, Error> {
        let mut parts: Vec<&str> = source_option.split(',').collect();
        if parts.len() == 3 {
            parts[2] = parts[2].trim_start_matches("sha256:");
        }
        Ok(DmVerityInfo {
            hashtype: "sha256".to_string(),
            blocksize: 512, //default block size
            hashsize: 4096, //default hash size
            blocknum: parts[0].parse()?,
            offset: parts[1].parse()?,
            hash: parts[2].to_string(),
        })
    }
}

// Parse `DmVerityInfo` object from plaintext or base64 encoded json string.
impl TryFrom<&str> for DmVerityInfo {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let option = if value.contains("sha256:") {
            Self::parse_tarfs_options(value)?
        } else if let Ok(v) = serde_json::from_str::<DmVerityInfo>(value) {
            v
        } else {
            let decoded = base64::engine::general_purpose::STANDARD.decode(value)?;
            serde_json::from_slice::<DmVerityInfo>(&decoded)?
        };

        option.validate()?;
        Ok(option)
    }
}

impl TryFrom<&String> for DmVerityInfo {
    type Error = Error;

    fn try_from(value: &String) -> std::result::Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

/// Creates a mapping with <name> backed by data_device <source_device_path>
/// and using hash_device for in-kernel verification.
/// It will return the verity block device Path "/dev/mapper/<name>"
/// Notes: the data device and the hash device are the same one.
pub fn create_verity_device(
    verity_option: &DmVerityInfo,
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
    let verity_table = vec![(
        0,
        verity_option.blocknum * verity_option.blocksize / 512,
        "verity".into(),
        verity_params,
    )];

    dm.device_create(verity_name, None, opts)?;
    dm.table_load(&id, verity_table.as_slice(), opts)?;
    dm.device_suspend(&id, opts)?;

    Ok(format!("/dev/mapper/{}", &verity_option.hash))
}

/// Destroy a DmVerity device with specified name.
pub fn destroy_verity_device(verity_device_name: String) -> Result<()> {
    let dm = devicemapper::DM::new()?;
    let name = devicemapper::DmName::new(&verity_device_name)?;

    dm.device_remove(
        &devicemapper::DevId::Name(name),
        devicemapper::DmOptions::default(),
    )
    .context(format!("remove DmverityDevice {}", verity_device_name))?;

    Ok(())
}

/// Get the DmVerity device name from option string.
pub fn get_verity_device_name(verity_options: &str) -> Result<String> {
    let option = DmVerityInfo::try_from(verity_options)?;
    Ok(option.hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn test_decode_verity_options() {
        let verity_option = DmVerityInfo {
            hashtype: "sha256".to_string(),
            blocksize: 512,
            hashsize: 512,
            blocknum: 16384,
            offset: 8388608,
            hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174".to_string(),
        };
        let json_option = serde_json::to_string(&verity_option).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&json_option);

        let decoded = DmVerityInfo::try_from(&encoded).unwrap_or_else(|err| panic!("{}", err));
        assert_eq!(decoded.hashtype, verity_option.hashtype);
        assert_eq!(decoded.blocksize, verity_option.blocksize);
        assert_eq!(decoded.hashsize, verity_option.hashsize);
        assert_eq!(decoded.blocknum, verity_option.blocknum);
        assert_eq!(decoded.offset, verity_option.offset);
        assert_eq!(decoded.hash, verity_option.hash);

        let decoded = DmVerityInfo::try_from(&json_option).unwrap();
        assert_eq!(decoded.hashtype, verity_option.hashtype);
        assert_eq!(decoded.blocksize, verity_option.blocksize);
        assert_eq!(decoded.hashsize, verity_option.hashsize);
        assert_eq!(decoded.blocknum, verity_option.blocknum);
        assert_eq!(decoded.offset, verity_option.offset);
        assert_eq!(decoded.hash, verity_option.hash);

        let verity_option =
            "1024,524288,sha256:9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174";
        let decoded = DmVerityInfo::try_from(verity_option).unwrap();
        assert_eq!(decoded.hashtype, "sha256");
        assert_eq!(decoded.blocksize, 512);
        assert_eq!(decoded.hashsize, 4096);
        assert_eq!(decoded.blocknum, 1024);
        assert_eq!(decoded.offset, 524288);
        assert_eq!(
            decoded.hash,
            "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
        );
    }

    #[tokio::test]
    async fn test_check_verity_options() {
        let tests = &[
            DmVerityInfo {
                hashtype: "md5".to_string(), // "md5" is not a supported hash algorithm
                blocksize: 512,
                hashsize: 512,
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityInfo {
                hashtype: "sha256".to_string(),
                blocksize: 3000, // Invalid block size, not a power of 2.
                hashsize: 512,
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityInfo {
                hashtype: "sha256".to_string(),
                blocksize: 0, // Invalid block size, less than 512.
                hashsize: 512,
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityInfo {
                hashtype: "sha256".to_string(),
                blocksize: 524800, // Invalid block size, greater than 524288.
                hashsize: 512,
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityInfo {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 3000, // Invalid hash block size, not a power of 2.
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityInfo {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 0, // Invalid hash block size, less than 512.
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityInfo {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 524800, // Invalid hash block size, greater than 524288.
                blocknum: 16384,
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityInfo {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 512,
                blocknum: 0, // Invalid blocknum, it must be greater than 0.
                offset: 8388608,
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityInfo {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 512,
                blocknum: 16384,
                offset: 0, // Invalid offset, it must be greater than 0.
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityInfo {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 512,
                blocknum: 16384,
                offset: 8193, // Invalid offset, it must be aligned to 512.
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
            DmVerityInfo {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 512,
                blocknum: 16384,
                offset: 8388608 - 4096, // Invalid offset, it must be equal to blocksize * blocknum.
                hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174"
                    .to_string(),
            },
        ];
        for d in tests.iter() {
            d.validate().unwrap_err();
        }
        let test_data = DmVerityInfo {
            hashtype: "sha256".to_string(),
            blocksize: 512,
            hashsize: 512,
            blocknum: 16384,
            offset: 8388608,
            hash: "9de18652fe74edfb9b805aaed72ae2aa48f94333f1ba5c452ac33b1c39325174".to_string(),
        };
        test_data.validate().unwrap();
    }

    #[tokio::test]
    async fn test_create_verity_device() {
        let work_dir = tempfile::tempdir().unwrap();
        let file_name: std::path::PathBuf = work_dir.path().join("test.file");
        let data = vec![0u8; 1048576];
        fs::write(&file_name, data)
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

        let tests = &[
            DmVerityInfo {
                hashtype: "sha256".to_string(),
                blocksize: 512,
                hashsize: 4096,
                blocknum: 1024,
                offset: 524288,
                hash: "fc65e84aa2eb12941aeaa29b000bcf1d9d4a91190bd9b10b5f51de54892952c6"
                    .to_string(),
            },
            DmVerityInfo {
                hashtype: "sha1".to_string(),
                blocksize: 512,
                hashsize: 1024,
                blocknum: 1024,
                offset: 524288,
                hash: "e889164102360c7b0f56cbef6880c4ae75f552cf".to_string(),
            },
        ];
        for d in tests.iter() {
            let verity_device_path =
                create_verity_device(d, &loop_device_path).unwrap_or_else(|err| panic!("{}", err));
            assert_eq!(verity_device_path, format!("/dev/mapper/{}", d.hash));
            destroy_verity_device(d.hash.clone()).unwrap();
        }
    }
}
