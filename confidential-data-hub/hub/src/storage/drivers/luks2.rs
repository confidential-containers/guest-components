// Copyright (c) 2024 Intel
// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # LUKS2
//!
//! This module leverages cryptsetup to encrypt/decrypt a block device with luks2.
//!
//! It requires to install dependency `libcryptsetup-dev` for ubuntu.

use std::path::Path;

use anyhow::Context;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64, Engine};
use const_format::concatcp;

use crate::hub::CDH_BASE_DIR;
use libcryptsetup_rs::consts::flags::{CryptActivate, CryptDeactivate, CryptVolumeKey};
use libcryptsetup_rs::consts::vals::EncryptionFormat;
use libcryptsetup_rs::{CryptInit, CryptParamsLuks2, CryptParamsLuks2Ref};
use tracing::debug;
use zeroize::Zeroizing;

/// Algorithm of the integrity hash
const HMAC_SHA256: &str = "hmac(sha256)";

/// The volume key size in bits with integrity
const LUKS2_VOLUME_KEY_SIZE_BIT_WITH_INTEGRITY: usize = 768;

/// The volume key size in bits without integrity
const LUKS2_VOLUME_KEY_SIZE_BIT_WITHOUT_INTEGRITY: usize = 256;

const SECTOR_SIZE: u32 = 4096;

pub const LUKS_HEADERS_STORAGE_DIR: &str = concatcp!(CDH_BASE_DIR, "/luks-headers");
pub const LUKS_HEADER_FILE_SUFFIX: &str = ".header";
pub const LUKS2_HEADER_MIN_SIZE_BYTES: u64 = 16 * 1024 * 1024;

/// Returns the path where the detached LUKS header for the given device is stored.
pub fn luks_header_path(device_path: &str) -> String {
    let name = b64.encode(device_path.as_bytes());
    format!(
        "{}/{}{}",
        LUKS_HEADERS_STORAGE_DIR, name, LUKS_HEADER_FILE_SUFFIX
    )
}

/// Creates and sizes the LUKS header file at `header_path`.
pub fn prepare_luks_header_file(header_path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(header_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    // error "LUKS header file not found: <path/to/header>" from libcryptsetup if header file doesn't exist.
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(header_path)?;
    // error "Device ... is too small" / OS error 5" from libcryptsetup if header isn't sized.
    file.set_len(LUKS2_HEADER_MIN_SIZE_BYTES)?;
    Ok(())
}

#[derive(Default)]
pub struct Luks2Formatter {
    pub integrity: bool,
}

impl Luks2Formatter {
    pub fn with_integrity(mut self, integrity: bool) -> Self {
        self.integrity = integrity;
        self
    }

    pub fn encrypt_device(
        &self,
        device_path: &str,
        header_path: Option<&str>,
        passphrase: Zeroizing<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let mut device = init_device(device_path, header_path)?;
        let mut volume_key_length = LUKS2_VOLUME_KEY_SIZE_BIT_WITHOUT_INTEGRITY / 8;
        let mut params = CryptParamsLuks2 {
            pbkdf: None,
            integrity: None,
            integrity_params: None,
            data_alignment: 0,
            data_device: None,
            sector_size: SECTOR_SIZE,
            label: None,
            subsystem: None,
        };

        if self.integrity {
            params.integrity = Some(HMAC_SHA256.to_string());
            volume_key_length = LUKS2_VOLUME_KEY_SIZE_BIT_WITH_INTEGRITY / 8;
        }

        device.context_handle().format(
            EncryptionFormat::Luks2,
            ("aes", "xts-plain"),
            None,
            libcryptsetup_rs::Either::Right(volume_key_length),
            Some(&mut TryInto::<CryptParamsLuks2Ref>::try_into(&params)?),
        )?;

        device
            .keyslot_handle()
            .add_by_key(None, None, &passphrase, CryptVolumeKey::empty())?;
        Ok(())
    }

    pub fn open_device(
        &self,
        device_path: &str,
        header_path: Option<&str>,
        name: &str,
        passphrase: Zeroizing<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let mut device = init_device(device_path, header_path)?;

        let mut params = CryptParamsLuks2 {
            pbkdf: None,
            integrity: None,
            integrity_params: None,
            data_alignment: 0,
            data_device: None,
            sector_size: SECTOR_SIZE,
            label: None,
            subsystem: None,
        };

        if self.integrity {
            params.integrity = Some(HMAC_SHA256.to_string());
        }

        device
            .context_handle()
            .load(
                Some(EncryptionFormat::Luks2),
                Some(&mut TryInto::<CryptParamsLuks2Ref>::try_into(&params)?),
            )
            .context("Failed to load LUKS2 device")?;

        debug!("activating device: {}", name);
        // We use NO_JOURNAL for performance
        device
            .activate_handle()
            .activate_by_passphrase(Some(name), None, &passphrase, CryptActivate::NO_JOURNAL)
            .context("Failed to activate LUKS2 device")?;
        debug!("device activated: {}", name);
        Ok(())
    }

    pub fn close_device(&self, name: &str) -> anyhow::Result<()> {
        let mut device = CryptInit::init_by_name_and_header(name, None)?;
        device
            .activate_handle()
            .deactivate(name, CryptDeactivate::empty())?;
        Ok(())
    }
}

fn init_device(
    device_path: &str,
    header_path: Option<&str>,
) -> anyhow::Result<libcryptsetup_rs::CryptDevice> {
    let device_path = Path::new(device_path);
    let device_paths = match header_path {
        Some(header_path) => libcryptsetup_rs::Either::Right((Path::new(header_path), device_path)),
        None => libcryptsetup_rs::Either::Left(device_path),
    };

    Ok(CryptInit::init_with_data_device(device_paths)?)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use serial_test::serial;
    use zeroize::Zeroizing;

    use super::{luks_header_path, prepare_luks_header_file, Luks2Formatter};

    const TEST_PASSPHRASE: &[u8] = b"test";
    const NAME: &str = "test";

    /// Removes the LUKS header file on drop so tests don't leave files behind on panic.
    struct RemoveHeaderOnDrop(String);
    impl Drop for RemoveHeaderOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Closes the dm-crypt device on drop so tests don't leave mapper devices behind.
    struct CloseDeviceOnDrop(String);
    impl Drop for CloseDeviceOnDrop {
        fn drop(&mut self) {
            let _ = Luks2Formatter::default().close_device(&self.0);
        }
    }

    #[test]
    #[serial]
    fn encrypt_open_device_no_integrity() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();

        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: false };
        luks2_formatter
            .encrypt_device(path, None, passphrase.clone())
            .unwrap();

        luks2_formatter
            .open_device(path, None, NAME, passphrase)
            .unwrap();
        let _device_guard = CloseDeviceOnDrop(NAME.to_string());
    }

    #[test]
    #[serial]
    fn encrypt_open_device_integrity() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();

        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: true };
        luks2_formatter
            .encrypt_device(path, None, passphrase.clone())
            .unwrap();

        luks2_formatter
            .open_device(path, None, NAME, passphrase)
            .unwrap();
        let _device_guard = CloseDeviceOnDrop(NAME.to_string());
    }

    #[test]
    #[serial]
    fn encrypt_open_device_no_integrity_with_header() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();
        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();
        let header_path = luks_header_path(path);
        prepare_luks_header_file(&header_path).unwrap();
        let _guard = RemoveHeaderOnDrop(header_path.clone());

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: false };
        luks2_formatter
            .encrypt_device(path, Some(&header_path), passphrase.clone())
            .unwrap();

        luks2_formatter
            .open_device(path, Some(&header_path), NAME, passphrase)
            .unwrap();
        let _device_guard = CloseDeviceOnDrop(NAME.to_string());
    }

    #[test]
    #[serial]
    fn encrypt_open_device_integrity_with_header() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();
        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();
        let header_path = luks_header_path(path);
        prepare_luks_header_file(&header_path).unwrap();
        let _guard = RemoveHeaderOnDrop(header_path.clone());

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: true };
        luks2_formatter
            .encrypt_device(path, Some(&header_path), passphrase.clone())
            .unwrap();

        luks2_formatter
            .open_device(path, Some(&header_path), NAME, passphrase)
            .unwrap();
        let _device_guard = CloseDeviceOnDrop(NAME.to_string());
    }

    #[test]
    #[serial]
    fn encrypt_with_existing_header_file() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();
        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();
        let header_path = luks_header_path(path);
        prepare_luks_header_file(&header_path).unwrap();
        let _guard = RemoveHeaderOnDrop(header_path.clone());

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: false };
        let result = luks2_formatter.encrypt_device(path, Some(&header_path), passphrase);
        assert!(result.is_ok());
    }

    #[test]
    #[serial]
    fn open_device_missing_header_file_fails() {
        let mut bin_file = tempfile::NamedTempFile::new().unwrap();
        bin_file
            .as_file_mut()
            .write_all(&vec![0; 20 * 1024 * 1024])
            .unwrap();
        let path = bin_file.path().to_str().unwrap();
        let header_path = luks_header_path(path);
        prepare_luks_header_file(&header_path).unwrap();
        let _guard = RemoveHeaderOnDrop(header_path.clone());

        let passphrase = Zeroizing::new(TEST_PASSPHRASE.to_vec());
        let luks2_formatter = Luks2Formatter { integrity: false };
        luks2_formatter
            .encrypt_device(path, Some(&header_path), passphrase.clone())
            .unwrap();

        std::fs::remove_file(&header_path).unwrap();

        let result =
            luks2_formatter.open_device(path, Some(header_path.as_str()), NAME, passphrase);
        assert!(result.is_err());
    }

    #[test]
    fn prepare_luks_header_file_rejects_existing_path() {
        use rand::{distr::Alphanumeric, rng, Rng};

        let path_str = format!(
            "/dev/{}",
            rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect::<String>()
        );

        let header_path = luks_header_path(&path_str);
        prepare_luks_header_file(&header_path).unwrap();
        let result = prepare_luks_header_file(&header_path);

        match result {
            Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists),
            other => panic!("unexpected result: {other:?}"),
        }
        let _ = std::fs::remove_file(&header_path);
    }

    /// This test can be used to clean useless devices under /dev/mapper/
    #[ignore]
    #[test]
    fn create_encrypt_close_test() {
        let luks2_formatter = Luks2Formatter { integrity: false };
        luks2_formatter
            .close_device("d7920c40-e7dc-48a4-aff7-6eab51c7d2d5")
            .unwrap();
    }
}
