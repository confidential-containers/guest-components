// Copyright (c) 2023 Alibaba Cloud
// Copyright (c) 2022 IBM Corp.
//
// SPDX-License-Identifier: Apache-2.0
//

//! This mod helps to initialize the SEV-ES security module.
//! see <https://www.kernel.org/doc/html/next/security/secrets/coco.html>
//! for more information.

use crate::{hub::Hub, Error, Result};

impl Hub {
    pub(crate) async fn init_sev() -> Result<()> {
        sev::mount_security_fs().map_err(|e| {
            Error::InitializationFailed(format!("sev mount security fs failed: {e}"))
        })?;
        let _secret_module = sev::SecretKernelModule::new().map_err(|e| {
            Error::InitializationFailed(format!("sev create SecretKernelModule failed: {e}"))
        })?;
        Ok(())
    }
}
