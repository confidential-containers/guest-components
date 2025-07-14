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

use libcryptsetup_rs::consts::flags::{CryptActivate, CryptDeactivate, CryptVolumeKey};
use libcryptsetup_rs::consts::vals::EncryptionFormat;
use libcryptsetup_rs::{CryptInit, CryptParamsLuks2, CryptParamsLuks2Ref};
use zeroize::Zeroizing;

/// Algorithm of the integrity hash
const HMAC_SHA256: &str = "hmac-sha256";

const SECTOR_SIZE: u32 = 4096;

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
        passphrase: Zeroizing<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let path = Path::new(device_path);
        let mut device = CryptInit::init(path)?;

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

        device.context_handle().format(
            EncryptionFormat::Luks2,
            ("aes", "xts-plain"),
            None,
            libcryptsetup_rs::Either::Right(256 / 8),
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
        name: &str,
        passphrase: Zeroizing<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let path = Path::new(device_path);
        let mut device = CryptInit::init(path)?;

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

        device.context_handle().load(
            Some(EncryptionFormat::Luks2),
            Some(&mut TryInto::<CryptParamsLuks2Ref>::try_into(&params)?),
        )?;

        // We use NO_JOURNAL for performance
        device.activate_handle().activate_by_passphrase(
            Some(name),
            None,
            &passphrase,
            CryptActivate::NO_JOURNAL,
        )?;
        Ok(())
    }

    pub fn close_device(&self, device_path: &str, name: &str) -> anyhow::Result<()> {
        let path = Path::new(device_path);
        let mut device = CryptInit::init(path)?;
        device
            .activate_handle()
            .deactivate(name, CryptDeactivate::empty())?;
        Ok(())
    }
}
