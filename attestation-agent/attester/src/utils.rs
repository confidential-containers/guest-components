// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{env, path::Path};

use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use tokio::{fs::File, io::AsyncReadExt};
use tracing::debug;

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

/// Validates and pads data to a specified size.
///
/// This function ensures that the input data does not exceed the expected size,
/// and pads it with zeros if it's smaller than the expected size.
///
/// # Arguments
///
/// * `data` - The input data to validate and pad
/// * `expected_size` - The target size for the data
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The validated and padded data
/// * `Err(anyhow::Error)` - If the data exceeds the expected size
pub fn validate_and_pad_data(data: Vec<u8>, expected_size: usize) -> Result<Vec<u8>> {
    match data.len() {
        len if len > expected_size => {
            bail!(
                "Invalid data length: expected {} bytes, got {} (too large)",
                expected_size,
                len
            )
        }
        len if len < expected_size => {
            debug!(
                "Padding data from {} to {} bytes with zeros",
                len, expected_size
            );
            let mut padded = data;
            padded.resize(expected_size, 0);
            Ok(padded)
        }
        _ => Ok(data), // Exact match, use as-is
    }
}

/// This is a fixed eventlog header. If no CCEL is found, we will use this header ahead
/// of aael eventlog.
///
/// The content of this HEADER is:
///
/// 1. EvNoAction entry
/// 2. Digest sizes with sha256 -> 0x20; sha384 -> 0x30; sm3 -> 0x20;
///
/// The digest algorithm is determined by OVMF/platform, and now:
/// - tdx supports sha384.
/// - csv supports sm3.
/// - az_snp_vtpm supports sha256.
///
/// All three algorithms are declared so the verifier's parser can size the
/// per-event digests of every TEE type that emits an AAEL. The TCG2 event
/// entries are self-describing (each carries its own algorithm id), so the
/// declaration order here does not need to match the event digest order.
///
/// Let's extend it if RTMR and CCEL are brought for more TEE types.
pub const EL_HEADER: [u8; 73] = [
    0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x20, 0x00,
    0x0C, 0x00, 0x30, 0x00, 0x12, 0x00, 0x20, 0x00, 0x00,
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
                0x12 => 0x20,
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

#[cfg(test)]
mod tests {
    use super::{trim_ccel, EL_HEADER};
    use std::collections::HashMap;

    // Builds a minimal TCG_PCR_EVENT spec-id header (EV_NO_ACTION, sha1 digest prefix).
    fn make_spec_id_header(event_data: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 4]; // pcrIndex = 0
        v.extend_from_slice(&3u32.to_le_bytes()); // eventType = EV_NO_ACTION
        v.extend_from_slice(&[0u8; 20]); // sha1_digest
        v.extend_from_slice(&(event_data.len() as u32).to_le_bytes());
        v.extend_from_slice(event_data);
        v
    }

    // Builds a minimal TCG_PCR_EVENT2 with one SHA-256 digest.
    fn make_sha256_event(target_mr: u32, event_data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&target_mr.to_le_bytes());
        v.extend_from_slice(&13u32.to_le_bytes()); // eventType
        v.extend_from_slice(&1u32.to_le_bytes()); // digestCount = 1
        v.extend_from_slice(&0x000Bu16.to_le_bytes()); // algId = SHA-256
        v.extend_from_slice(&[0xABu8; 32]); // digest
        v.extend_from_slice(&(event_data.len() as u32).to_le_bytes());
        v.extend_from_slice(event_data);
        v
    }

    /// Guards the hand-computed byte offsets of the eventlog spec-id header and
    /// asserts it declares SHA-256, so the verifier parser can size the SHA-256
    /// digests emitted by vTPM-based attesters (e.g. az_snp_vtpm) instead of
    /// bailing on the first runtime event.
    #[test]
    fn test_el_header_declares_sha256() {
        // TCG_PCR_EVENT prefix: pcrIndex(4) + eventType(4) + digest[20] + eventDataSize(4) = 32
        assert_eq!(EL_HEADER.len(), 73);

        // eventType == EV_NO_ACTION (3)
        assert_eq!(u32::from_le_bytes(EL_HEADER[4..8].try_into().unwrap()), 3);

        // eventDataSize (offset 28) counts the TCG_EfiSpecIDEvent that follows.
        let event_data_size = u32::from_le_bytes(EL_HEADER[28..32].try_into().unwrap());
        assert_eq!(event_data_size, 41);
        assert_eq!(EL_HEADER.len(), 32 + event_data_size as usize);

        // numberOfAlgorithms (offset 56) == 3
        let num_algs = u32::from_le_bytes(EL_HEADER[56..60].try_into().unwrap());
        assert_eq!(num_algs, 3);

        // digestSizes entries (u16 algId + u16 digestSize) begin at offset 60.
        let mut algs = HashMap::new();
        for i in 0..num_algs as usize {
            let base = 60 + i * 4;
            let alg = u16::from_le_bytes(EL_HEADER[base..base + 2].try_into().unwrap());
            let size = u16::from_le_bytes(EL_HEADER[base + 2..base + 4].try_into().unwrap());
            algs.insert(alg, size);
        }
        assert_eq!(algs.get(&0x000B), Some(&32)); // SHA-256
        assert_eq!(algs.get(&0x000C), Some(&48)); // SHA-384
        assert_eq!(algs.get(&0x0012), Some(&32)); // SM3

        // vendorInfoSize (final byte) == 0
        assert_eq!(*EL_HEADER.last().unwrap(), 0);
    }

    #[test]
    fn trim_ccel_strips_end_flag_and_padding() {
        let header = make_spec_id_header(&[]);
        let event = make_sha256_event(7, &[1, 2, 3, 4]);
        let expected: Vec<u8> = [header.as_slice(), event.as_slice()].concat();

        let mut ccel = expected.clone();
        ccel.extend_from_slice(&[0xFFu8; 8]); // end flag
        ccel.extend_from_slice(&[0u8; 64]); // trailing padding

        assert_eq!(trim_ccel(ccel).unwrap(), expected);
    }

    #[test]
    fn trim_ccel_zero_end_flag() {
        let header = make_spec_id_header(&[]);
        let event = make_sha256_event(7, &[]);
        let expected: Vec<u8> = [header.as_slice(), event.as_slice()].concat();

        let mut ccel = expected.clone();
        ccel.extend_from_slice(&[0u8; 8]); // zero end flag

        assert_eq!(trim_ccel(ccel).unwrap(), expected);
    }

    #[test]
    fn trim_ccel_no_runtime_events() {
        let header = make_spec_id_header(&[]);
        let mut ccel = header.clone();
        ccel.extend_from_slice(&[0xFFu8; 8]);

        assert_eq!(trim_ccel(ccel).unwrap(), header);
    }

    #[test]
    fn trim_ccel_too_short_returns_err() {
        assert!(trim_ccel(vec![0u8; 4]).is_err());
    }

    #[test]
    fn trim_ccel_no_end_flag_returns_err() {
        // header only, no end flag — loop bails on missing terminator
        assert!(trim_ccel(make_spec_id_header(&[])).is_err());
    }

    #[test]
    fn trim_ccel_unsupported_algorithm_returns_err() {
        let header = make_spec_id_header(&[]);
        let mut event = Vec::new();
        event.extend_from_slice(&7u32.to_le_bytes()); // target_mr
        event.extend_from_slice(&13u32.to_le_bytes()); // event_type
        event.extend_from_slice(&1u32.to_le_bytes()); // digestCount = 1
        event.extend_from_slice(&0x0001u16.to_le_bytes()); // algId = unknown
        event.extend_from_slice(&[0u8; 20]); // padding (never reached)

        let mut ccel = header;
        ccel.extend_from_slice(&event);

        assert!(trim_ccel(ccel).is_err());
    }
}
