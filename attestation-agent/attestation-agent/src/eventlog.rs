// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{fmt::Display, fs::File, io::Write};

use anyhow::{bail, Context, Result};
use const_format::concatcp;

use crypto::HashAlgorithm;

/// AA's eventlog will be put into this parent directory
pub const EVENTLOG_PARENT_DIR_PATH: &str = "/run/attestation-agent";

/// AA's eventlog will be stored inside the file
pub const EVENTLOG_PATH: &str = concatcp!(EVENTLOG_PARENT_DIR_PATH, "/eventlog");

pub struct EventLog {
    writer: Box<dyn Writer>,
}

trait Writer: Sync + Send {
    fn append(&mut self, entry: &LogEntry) -> Result<()>;
}

pub struct FileWriter {
    file: File,
}

impl Writer for FileWriter {
    fn append(&mut self, entry: &LogEntry) -> Result<()> {
        writeln!(self.file, "{entry}").context("failed to write log")?;
        self.file
            .flush()
            .context("failed to flush log to I/O media")?;
        Ok(())
    }
}

impl EventLog {
    pub fn new() -> Result<Self> {
        std::fs::create_dir_all(EVENTLOG_PARENT_DIR_PATH).context("create eventlog parent dir")?;
        let file = File::create(EVENTLOG_PATH).context("create eventlog")?;
        let writer = Box::new(FileWriter { file });
        Ok(Self { writer })
    }

    pub fn write_log(&mut self, entry: &LogEntry) -> Result<()> {
        self.writer.append(entry)
    }
}

pub struct Content<'a>(&'a str);

impl<'a> TryFrom<&'a str> for Content<'a> {
    type Error = anyhow::Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if value.chars().any(|c| c == '\n') {
            bail!("content contains newline");
        }
        Ok(Content(value))
    }
}

pub enum LogEntry<'a> {
    Event {
        domain: &'a str,
        operation: &'a str,
        content: Content<'a>,
    },
    Init(HashAlgorithm),
}

impl<'a> LogEntry<'a> {
    /// Calculate the LogEntry's digest with the given [`HashAlgorithm`]
    pub fn digest_with(&self, hash_alg: HashAlgorithm) -> Vec<u8> {
        let log_entry = self.to_string();
        hash_alg.digest(log_entry.as_bytes())
    }
}

impl<'a> Display for LogEntry<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogEntry::Event {
                domain,
                operation,
                content,
            } => {
                write!(f, "{} {} {}", domain, operation, content.0)
            }
            LogEntry::Init(hash_alg) => {
                // TODO: We should get the current platform's evidence to
                // see the RTMR value. Here we assume RTMR is not polluted
                // thus all be set `\0`
                let (sha, zeroes) = match hash_alg {
                    HashAlgorithm::Sha256 => ("sha256", "0".repeat(64)),
                    HashAlgorithm::Sha384 => ("sha384", "0".repeat(96)),
                    HashAlgorithm::Sha512 => ("sha512", "0".repeat(128)),
                };
                write!(f, "INIT {}/{}", sha, zeroes)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::sync::{Arc, Mutex};

    struct TestWriter(Arc<Mutex<Vec<String>>>);

    impl Writer for TestWriter {
        fn append(&mut self, entry: &LogEntry) -> Result<()> {
            self.0.lock().unwrap().push(entry.to_string());
            Ok(())
        }
    }

    #[test]
    fn test_content() {
        let a_str = "hello";
        let _: Content = a_str.try_into().unwrap();
        let b_str = "hello\nworld";
        let content: Result<Content, _> = b_str.try_into();
        assert!(content.is_err());
    }

    #[test]
    fn test_log_events() {
        let lines = Arc::new(Mutex::new(vec![]));
        let tw = TestWriter(lines.clone());
        let mut el = EventLog {
            writer: Box::new(tw),
        };
        let i = LogEntry::Init(HashAlgorithm::Sha256);
        el.write_log(&i).unwrap();
        let i_line = concat!(
            "INIT sha256/00000000000000000000000000",
            "00000000000000000000000000000000000000"
        );
        assert_eq!(lines.lock().unwrap().join("\n"), i_line);
        let ev = LogEntry::Event {
            domain: "one",
            operation: "two",
            content: "three".try_into().unwrap(),
        };
        el.write_log(&ev).unwrap();
        let e_line = "one two three";
        assert_eq!(lines.lock().unwrap()[1], e_line);
    }

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
        let event = LogEntry::Event {
            domain,
            operation,
            content: content.try_into().unwrap(),
        };
        let dig = event.digest_with(hash_alg);
        let dig_hex = dig.iter().map(|c| format!("{c:02x}")).collect::<String>();
        assert_eq!(dig_hex, digest);
    }
}
