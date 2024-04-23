// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{fmt::Display, fs::File, io::Write};

use anyhow::{Context, Result};
use const_format::concatcp;

use crate::config::HashAlgorithm;

/// AA's eventlog will be put into this parent directory
pub const EVENTLOG_PARENT_DIR_PATH: &str = "/run/attestation-agent";

/// AA's eventlog will be stored inside the file
pub const EVENTLOG_PATH: &str = concatcp!(EVENTLOG_PARENT_DIR_PATH, "/eventlog");

pub struct EventLog {
    file: File,
}

impl EventLog {
    pub fn new() -> Result<Self> {
        std::fs::create_dir_all(EVENTLOG_PARENT_DIR_PATH).context("create eventlog parent dir")?;
        let file = File::create(EVENTLOG_PATH).context("create eventlog")?;
        Ok(Self { file })
    }

    pub fn write_log(&mut self, log: &str) -> Result<()> {
        writeln!(self.file, "{log}").context("failed to write log")?;
        self.file
            .flush()
            .context("failed to flush log to I/O media")?;
        Ok(())
    }
}

pub struct EventEntry<'a> {
    domain: &'a str,
    operation: &'a str,
    content: &'a str,
}

impl<'a> EventEntry<'a> {
    pub fn new(domain: &'a str, operation: &'a str, content: &'a str) -> Self {
        Self {
            domain,
            operation,
            content,
        }
    }

    /// Calculate the EventEntry's digest with the given [`HashAlgorithm`]
    pub fn digest_with(&self, hash_alg: HashAlgorithm) -> Vec<u8> {
        let log_entry = self.to_string();
        hash_alg.digest(log_entry.as_bytes())
    }
}

impl<'a> Display for EventEntry<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.domain, self.operation, self.content)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::config::HashAlgorithm;

    use super::EventEntry;

    #[rstest]
    #[case(
        "domain",
        "operation",
        "content",
        "65aad3b1620d4fe224d727579db2db87ff5c033f3e4424ae0fd72eb1149d3bd5",
        HashAlgorithm::Sha256
    )]
    #[case("domain", "operation", "content", "26d944cb8d99096590252283b8c807b9508329b068703bdb7bac7eb6efe5b32fc0fadf1462662b95d2c708aa49c0bfe1", HashAlgorithm::Sha384)]
    #[case("domain", "operation", "content", "6e75837e0fbf8367fa4550254b8f0f52eb659be0901340357ed91dda97f0ebca10537540a021eec78df9d29ade51609a01eaaa46d32e0218cdac1644dc9933b0", HashAlgorithm::Sha512)]
    fn test_event_digest(
        #[case] domain: &str,
        #[case] operation: &str,
        #[case] content: &str,
        #[case] digest: &str,
        #[case] hash_alg: HashAlgorithm,
    ) {
        let event = EventEntry::new(domain, operation, content);
        let dig = event.digest_with(hash_alg);
        let dig_hex = dig.iter().map(|c| format!("{c:02x}")).collect::<String>();
        assert_eq!(dig_hex, digest);
    }
}
