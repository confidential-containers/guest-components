// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Context};
use scroll::Pread;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::tdx::TdxAttester;

use std::path::Path;

const CCEL_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";

/// Path to the ACPI table CCEL description
const CCEL_ACPI_DESCRIPTION: &str = "/sys/firmware/acpi/tables/CCEL";

/// Guest memory which is used to read the CCEL
const GUEST_MEMORY: &str = "/dev/mem";

/// Signature of CCEL's ACPI Description Header
const CCEL_SIGNATURE: &[u8] = b"CCEL";

#[repr(C)]
#[derive(Pread)]
struct EfiAcpiDescriptionHeader {
    signature: u32,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: u64,
    oem_revision: u32,
    craetor_id: u32,
    creator_revision: u32,
}

#[repr(C)]
#[derive(Pread)]
struct TdxEventLogACPITable {
    efi_acpi_description_header: EfiAcpiDescriptionHeader,
    rsv: u32,
    laml: u64,
    lasa: u64,
}

impl TdxAttester {
    pub async fn read_ccel() -> anyhow::Result<Vec<u8>> {
        if Path::new(CCEL_PATH).exists() {
            let ccel = tokio::fs::read(CCEL_PATH).await?;
            return Ok(ccel);
        }

        let efi_acpi_description = tokio::fs::read(CCEL_ACPI_DESCRIPTION)
            .await
            .context("read ccel description")?;
        let ccel_acpi_table = efi_acpi_description
            .pread::<TdxEventLogACPITable>(0)
            .context("parse CCEL ACPI description failed")?;

        let ccel_signature = u32::from_le_bytes(CCEL_SIGNATURE.try_into()?);
        if ccel_acpi_table.efi_acpi_description_header.signature != ccel_signature {
            bail!("invalid CCEL ACPI table: wrong CCEL signature");
        }

        if ccel_acpi_table.rsv != 0 {
            bail!("invalid CCEL ACPI table: RSV must be 0");
        }

        if ccel_acpi_table.efi_acpi_description_header.length != efi_acpi_description.len() as u32 {
            bail!("invalid CCEL ACPI table: header length not match");
        }

        let mut guest_memory = tokio::fs::OpenOptions::new()
            .read(true)
            .open(GUEST_MEMORY)
            .await?;
        guest_memory
            .seek(std::io::SeekFrom::Start(ccel_acpi_table.lasa))
            .await?;
        let mut ccel = vec![0; ccel_acpi_table.laml as usize];
        let read_size = guest_memory.read(&mut ccel).await?;
        if read_size == 0 {
            bail!("read CCEL failed");
        }

        Ok(ccel)
    }
}

#[cfg(test)]
mod tests {
    use crate::tdx::TdxAttester;

    #[ignore]
    #[tokio::test]
    async fn test_read_ccel() {
        let _ccel = TdxAttester::read_ccel().await.unwrap();
    }
}
