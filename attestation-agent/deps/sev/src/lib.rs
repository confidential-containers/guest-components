// Copyright (c) 2022 IBM Corp.
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use std::process::Command;

const SECRET_MODULE_NAME: &str = "efi_secret";
const MODPROBE_PATH: &str = "/sbin/modprobe";
const MOUNT_PATH: &str = "/bin/mount";

pub struct SecretKernelModule;

impl SecretKernelModule {
    pub fn new() -> Result<SecretKernelModule> {
        if !Command::new(MODPROBE_PATH)
            .arg(SECRET_MODULE_NAME)
            .status()?
            .success()
        {
            return Err(anyhow!("Failed to load secret module."));
        }
        Ok(SecretKernelModule {})
    }
}
impl Drop for SecretKernelModule {
    fn drop(&mut self) {
        Command::new(MODPROBE_PATH)
            .arg("-r")
            .arg(SECRET_MODULE_NAME)
            .status()
            .expect("Failed to unload secret module.");
    }
}

pub fn mount_security_fs() -> Result<()> {
    if !Command::new(MOUNT_PATH)
        .arg("-t")
        .arg("securityfs")
        .arg("securityfs")
        .arg("/sys/kernel/security")
        .status()?
        .success()
    {
        return Err(anyhow!("Failed to mount security fs"));
    }
    Ok(())
}
