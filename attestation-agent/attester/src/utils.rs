// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{env, path::Path};

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use tokio::{fs::File, io::AsyncReadExt};

pub fn pad<const T: usize>(input: &[u8]) -> [u8; T] {
    let mut output = [0; T];
    let len = input.len();
    if len > T {
        output.copy_from_slice(&input[..T]);
    } else {
        output[..len].copy_from_slice(input);
    }
    output
}

/// This is a fixed eventlog header. If no CCEL is found, we will use this header ahead
/// of aael eventlog.
///
/// The content of this HEADER is:
///
/// 1. EvNoAction entry
/// 2. Digest sizes with sha384 -> 0x30
///
/// TODO: apply hash algorithm based on the underlying platform.
/// Now the digests declared by CCEL might be different from the AAEL (defaults to sha384).
/// This would cause the integrity check to fail.
///
/// The digest algorithm is determined by OVMF, and now tdx supports sha384. Let's extend it
/// if RTMR and CCEL are brought for TEE except TDX.
pub const EL_HEADER: [u8; 65] = [
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x30, 0x00,
    0x00,
];

/// End flag for eventlog
pub const EL_END_FLAG: [u8; 8] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

pub const DEFAULT_AAEL_PATH: &str = "/run/attestation-agent/eventlog";

const CCEL_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";

fn trim_ccel(mut ccel: Vec<u8>) -> Result<Vec<u8>> {
    let ccel_len = ccel.len();
    let mut index = 4;
    if ccel_len < index + size_of::<u32>() {
        bail!("invalid ccel: not enough length");
    }
    let event_type_num = u32::from_le_bytes(
        ccel[index..index + size_of::<u32>()]
            .try_into()
            .expect("slice must be 4 bytes"),
    );
    index += size_of::<u32>();
    index += 20;

    // if it is EV_NO_ACTION
    if event_type_num == 0x3 {
        if ccel_len < index + size_of::<u32>() {
            bail!("invalid ccel: not enough length");
        }
        let event_data_size = u32::from_le_bytes(
            ccel[index..index + size_of::<u32>()]
                .try_into()
                .expect("slice must be 4 bytes"),
        );
        index += size_of::<u32>();
        index += event_data_size as usize;
    }

    loop {
        if ccel_len < index + size_of::<u64>() {
            bail!("invalid ccel: no end flag");
        }
        let stop_flag = u64::from_le_bytes(
            ccel[index..index + size_of::<u64>()]
                .try_into()
                .expect("slice must be 8 bytes"),
        );

        if stop_flag == 0xFFFFFFFFFFFFFFFF || stop_flag == 0x0000000000000000 {
            ccel.resize(index, b'\0');
            return Ok(ccel);
        }

        // skip target mr, event type
        index += size_of::<u32>() + size_of::<u32>();
        if ccel_len < index + size_of::<u32>() {
            bail!("invalid ccel: no digest length");
        }
        let digests_length = u32::from_le_bytes(
            ccel[index..index + size_of::<u32>()]
                .try_into()
                .expect("slice must be 4 bytes"),
        );
        index += size_of::<u32>();

        for _ in 0..digests_length {
            if ccel_len < index + size_of::<u16>() {
                bail!("invalid ccel: no digest algorithm");
            }
            let digest_type = u16::from_le_bytes(
                ccel[index..index + size_of::<u16>()]
                    .try_into()
                    .expect("slice must be 2 bytes"),
            );
            index += size_of::<u16>();
            let digest_lenth = match digest_type {
                0xb => 0x20,
                0xc => 0x30,
                0xd => 0x40,
                _ => {
                    bail!("invalid ccel: unsupported digest algorithm");
                }
            };

            index += digest_lenth;
        }

        if ccel_len < index + size_of::<u32>() {
            bail!("invalid ccel: no event data size");
        }
        let event_data_size = u32::from_le_bytes(
            ccel[index..index + size_of::<u32>()]
                .try_into()
                .expect("slice must be 4 bytes"),
        );
        index += size_of::<u32>();
        index += event_data_size as usize;
    }
}

pub async fn read_eventlog() -> Result<Option<String>> {
    let aael_path = env::var("AAEL_PATH").unwrap_or(DEFAULT_AAEL_PATH.to_string());
    let mut eventlog = Vec::new();
    if Path::new(CCEL_PATH).exists() {
        let mut file = File::open(CCEL_PATH).await?;
        file.read_to_end(&mut eventlog).await?;
        eventlog = trim_ccel(eventlog)?;
    }

    if Path::new(&aael_path).exists() {
        let mut file = File::open(aael_path).await?;
        if eventlog.is_empty() {
            eventlog.extend_from_slice(&EL_HEADER);
        }
        file.read_to_end(&mut eventlog).await?;
    }

    if eventlog.is_empty() {
        return Ok(None);
    }

    eventlog.extend_from_slice(&EL_END_FLAG);

    Ok(Some(STANDARD.encode(eventlog)))
}
