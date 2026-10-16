// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Context, Result, bail};
use kbs_types::HashAlgorithm;
use serde::Serialize;

use crate::eventlog::Event;

#[repr(u16)]
#[derive(Debug, Clone, Hash, Copy, PartialEq, Eq, Serialize)]
pub enum TcgAlgorithm {
    #[serde(rename = "SHA-256")]
    Sha256 = 0xB,

    #[serde(rename = "SHA-384")]
    Sha384 = 0xC,

    #[serde(rename = "SHA-512")]
    Sha512 = 0xD,

    #[serde(rename = "SM3")]
    Sm3 = 0x12,
}

impl From<HashAlgorithm> for TcgAlgorithm {
    fn from(value: HashAlgorithm) -> Self {
        match value {
            HashAlgorithm::Sha256 => TcgAlgorithm::Sha256,
            HashAlgorithm::Sha384 => TcgAlgorithm::Sha384,
            HashAlgorithm::Sha512 => TcgAlgorithm::Sha512,
            HashAlgorithm::Sm3 => TcgAlgorithm::Sm3,
        }
    }
}

impl TcgAlgorithm {
    pub const fn to_le_bytes(self) -> [u8; 2] {
        (self as u16).to_le_bytes()
    }
}

#[derive(Debug, Clone)]
pub struct ElDigest {
    pub alg: TcgAlgorithm,
    pub digest: Vec<u8>,
}

impl ElDigest {
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend_from_slice(&self.alg.to_le_bytes());
        result.extend_from_slice(&self.digest);
        result
    }
}

/// A TCG2 Event Entry struct, with event type `EV_EVENT_TAG`.
/// This is a wrapper of AAEL.
///
/// The event data section is the AAEL plaintext.
pub struct Tcg2EventEntry {
    /// The target measurement register number.
    target_measurement_register: u32,

    /// The type number of the event.
    event_type_num: u32,

    /// The number of digests in the digest list.
    digest_count: u32,

    /// The digest of the event data section.
    digest: Vec<ElDigest>,

    /// The length of the event data section.
    event_data_length: u32,

    /// The event data section.
    event_data: Vec<u8>,
}

impl Tcg2EventEntry {
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.target_measurement_register.to_le_bytes());
        bytes.extend_from_slice(&self.event_type_num.to_le_bytes());
        bytes.extend_from_slice(&self.digest_count.to_le_bytes());

        for digest in &self.digest {
            bytes.extend_from_slice(&digest.to_le_bytes());
        }

        bytes.extend_from_slice(&self.event_data_length.to_le_bytes());
        bytes.extend_from_slice(&self.event_data);
        bytes
    }
}

pub struct TaggedEvent {
    /// Tagged event id. For AAEL it is b'AAEL'
    tagged_id: u32,

    /// The length of `event_data` field
    tagged_event_size: u32,

    /// AAEL plaintext
    event_data: Vec<u8>,
}

impl TaggedEvent {
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend_from_slice(&self.tagged_id.to_le_bytes());
        result.extend_from_slice(&self.tagged_event_size.to_le_bytes());
        result.extend_from_slice(&self.event_data);
        result
    }
}

/// Tagged event type ID
const EV_EVENT_TAG_TYPE: u32 = 0x6;

/// AAEL tagged event ID, ASCII of `"AAEL"`
const AAEL_TAGGED_EVENT_ID: u32 = 0x4141454c;

impl<'a> From<Event<'a>> for Tcg2EventEntry {
    fn from(value: Event<'a>) -> Self {
        let event_data = value.to_string().into_bytes();
        let tagged_event = TaggedEvent {
            tagged_id: AAEL_TAGGED_EVENT_ID,
            tagged_event_size: event_data.len() as u32,
            event_data,
        };

        let event_data = tagged_event.to_le_bytes();
        Tcg2EventEntry {
            target_measurement_register: 1,
            event_type_num: EV_EVENT_TAG_TYPE,
            digest_count: 0,
            digest: vec![],
            event_data_length: event_data.len() as u32,
            event_data,
        }
    }
}

impl Tcg2EventEntry {
    pub fn with_target_measurement_register(mut self, target_measurement_register: u32) -> Self {
        self.target_measurement_register = target_measurement_register;
        self
    }

    pub fn digest(mut self, algorithm: HashAlgorithm) -> (Self, Vec<u8>) {
        self.digest_count = 1;
        let digest = algorithm.digest(&self.event_data);
        let el_digest = ElDigest {
            alg: algorithm.into(),
            digest: digest.clone(),
        };
        self.digest = vec![el_digest];
        (self, digest)
    }
}

/// Return the AAEL plaintext of each entry in a log written by `EventLog`.
///
/// Every entry has the shape `Tcg2EventEntry::to_le_bytes` produces, so a truncated tail
/// or any unexpected header is an error rather than something to skip.
pub fn aael_plaintexts(mut log: &[u8]) -> Result<Vec<&str>> {
    fn take<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
        if buf.len() < n {
            bail!("truncated AAEL entry");
        }
        let (head, tail) = buf.split_at(n);
        *buf = tail;
        Ok(head)
    }
    fn u32_le(buf: &mut &[u8]) -> Result<u32> {
        Ok(u32::from_le_bytes(take(buf, 4)?.try_into()?))
    }

    let mut plaintexts = vec![];
    while !log.is_empty() {
        let _register = u32_le(&mut log)?;
        let event_type = u32_le(&mut log)?;
        let digest_count = u32_le(&mut log)?;
        if event_type != EV_EVENT_TAG_TYPE || digest_count != 1 {
            bail!("unexpected AAEL entry header");
        }
        let digest_len = match u16::from_le_bytes(take(&mut log, 2)?.try_into()?) {
            0xB | 0x12 => 32,
            0xC => 48,
            0xD => 64,
            alg => bail!("unknown AAEL digest algorithm {alg:#x}"),
        };
        take(&mut log, digest_len)?;
        let data_len = u32_le(&mut log)? as usize;
        let mut data = take(&mut log, data_len)?;
        let tag = u32_le(&mut data)?;
        if tag != AAEL_TAGGED_EVENT_ID || u32_le(&mut data)? as usize != data.len() {
            bail!("malformed AAEL tagged event");
        }
        plaintexts.push(std::str::from_utf8(data).context("AAEL plaintext is not UTF-8")?);
    }
    Ok(plaintexts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // Byte offsets in a SHA-384 entry, as `Tcg2EventEntry::to_le_bytes` lays it out.
    const EVENT_TYPE: usize = 4;
    const DIGEST_COUNT: usize = 8;
    const ALGORITHM: usize = 12;
    const TAG: usize = 66;
    const TEXT_LEN: usize = 70;

    fn entry(content: &str) -> Vec<u8> {
        let event = Event::new("domain", "operation", content).unwrap();
        let (entry, _) = Tcg2EventEntry::from(event)
            .with_target_measurement_register(4)
            .digest(HashAlgorithm::Sha384);
        entry.to_le_bytes()
    }

    fn set_u32(entry: &mut [u8], at: usize, value: u32) {
        entry[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn test_aael_plaintexts_reads_every_entry() {
        let log = [entry("one"), entry("two")].concat();
        assert_eq!(
            aael_plaintexts(&log).unwrap(),
            ["domain operation one", "domain operation two"]
        );
    }

    #[rstest]
    #[case::truncated(|e: &mut Vec<u8>| { e.pop(); })]
    #[case::event_type(|e: &mut Vec<u8>| set_u32(e, EVENT_TYPE, 1))]
    #[case::digest_count(|e: &mut Vec<u8>| set_u32(e, DIGEST_COUNT, 2))]
    #[case::algorithm(|e: &mut Vec<u8>| e[ALGORITHM..ALGORITHM + 2].copy_from_slice(&4u16.to_le_bytes()))]
    #[case::tag(|e: &mut Vec<u8>| set_u32(e, TAG, 0))]
    #[case::text_len(|e: &mut Vec<u8>| set_u32(e, TEXT_LEN, 4))]
    #[case::not_utf8(|e: &mut Vec<u8>| *e.last_mut().unwrap() = 0xff)]
    fn test_aael_plaintexts_rejects_a_malformed_entry(#[case] corrupt: fn(&mut Vec<u8>)) {
        let mut bad = entry("two");
        corrupt(&mut bad);
        let log = [entry("one"), bad].concat();
        assert!(aael_plaintexts(&log).is_err());
    }
}
