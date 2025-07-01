// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod event;

use std::{
    fmt::Display,
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    str::FromStr,
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use attester::CompositeAttester;
use const_format::concatcp;

use crypto::HashAlgorithm;
use event::AAEventlog;
use log::debug;

/// AA's eventlog will be put into this parent directory
pub const EVENTLOG_PARENT_DIR_PATH: &str = "/run/attestation-agent";

/// AA's eventlog will be stored inside the file
pub const EVENTLOG_PATH: &str = concatcp!(EVENTLOG_PARENT_DIR_PATH, "/eventlog");

pub struct EventLog {
    writer: Box<dyn Writer>,
    rtmr_extender: Arc<CompositeAttester>,
    alg: HashAlgorithm,
    pcr: u64,
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
    pub async fn new(
        rtmr_extender: Arc<CompositeAttester>,
        alg: HashAlgorithm,
        pcr: u64,
    ) -> Result<Self> {
        tokio::fs::create_dir_all(EVENTLOG_PARENT_DIR_PATH)
            .await
            .context("create eventlog parent dir")?;
        if Path::new(EVENTLOG_PATH).exists() {
            debug!("Previous AAEL found. Skip INIT entry recording...");
            let content = tokio::fs::read_to_string(EVENTLOG_PATH)
                .await
                .context("Read AAEL")?;

            // The content of AAEL can be empty when the previous AA created this file
            // but did not do anything.
            if content.is_empty() {
                let file = File::options()
                    .write(true)
                    .open(EVENTLOG_PATH)
                    .context("open eventlog")?;
                let mut eventlog = Self {
                    writer: Box::new(FileWriter { file }),
                    rtmr_extender,
                    alg,
                    pcr,
                };
                eventlog
                    .extend_init_entry()
                    .await
                    .context("extend INIT entry")?;
                return Ok(eventlog);
            }

            let aael = AAEventlog::from_str(&content).context("Parse AAEL")?;
            let rtmr = rtmr_extender
                .get_runtime_measurement(pcr)
                .await
                .context("Get RTMR failed")?;

            // The integrity check might fail when previous AA record the entry into
            // aael but failed to extend RTMR. This check will try to catch this case
            // and do then unfinished RTMR extending.
            match aael.integrity_check(&rtmr) {
                true => debug!("Existing RTMR is consistent with current AAEL"),
                false => {
                    debug!(
                        "Existing RTMR is not consistent with current AAEL, do a RTMR extending..."
                    );
                    let digest = match aael.events.is_empty() {
                        true => alg.digest(
                            format!(
                                "INIT {}/{:0>width$}",
                                aael.hash_algorithm,
                                hex::encode(aael.init_state),
                                width = aael.hash_algorithm.digest_len()
                            )
                            .as_bytes(),
                        ),
                        false => alg.digest(aael.events[0].as_bytes()),
                    };
                    rtmr_extender
                        .extend_runtime_measurement(digest, pcr)
                        .await
                        .context("Extend RTMR failed")?;
                }
            }

            let file = OpenOptions::new()
                .append(true)
                .open(EVENTLOG_PATH)
                .context("open eventlog")?;

            return Ok(Self {
                writer: Box::new(FileWriter { file }),
                rtmr_extender,
                alg,
                pcr,
            });
        }

        debug!("No AA eventlog exists, creating a new one and do INIT entry recording...");
        let file = File::create(EVENTLOG_PATH).context("create eventlog")?;
        let writer = Box::new(FileWriter { file });
        let mut eventlog = Self {
            writer,
            rtmr_extender,
            alg,
            pcr,
        };
        eventlog
            .extend_init_entry()
            .await
            .context("extend INIT entry")?;
        Ok(eventlog)
    }

    pub async fn extend_entry(&mut self, log_entry: LogEntry<'_>, pcr: u64) -> Result<()> {
        let digest = log_entry.digest_with(self.alg);
        // The order must be ensured to keep consistency. s.t. first write AAEL
        // and then extend RTMR.
        self.writer.append(&log_entry).context("write log entry")?;
        self.rtmr_extender
            .extend_runtime_measurement(digest, pcr)
            .await?;

        Ok(())
    }

    pub async fn extend_init_entry(&mut self) -> Result<()> {
        let pcr = self.rtmr_extender.get_runtime_measurement(self.pcr).await?;
        let init_value = hex::encode(pcr);
        let init_value = format!("{:0>width$}", init_value, width = self.alg.digest_len());
        let init_entry = LogEntry::Init {
            hash_alg: self.alg,
            value: &init_value,
        };
        let digest = init_entry.digest_with(self.alg);
        self.writer
            .append(&init_entry)
            .context("write INIT log entry")?;

        self.rtmr_extender
            .extend_runtime_measurement(digest, self.pcr)
            .await
            .context("write INIT entry")?;
        Ok(())
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
    Init {
        hash_alg: HashAlgorithm,
        value: &'a str,
    },
}

impl LogEntry<'_> {
    /// Calculate the LogEntry's digest with the given [`HashAlgorithm`]
    pub fn digest_with(&self, hash_alg: HashAlgorithm) -> Vec<u8> {
        let log_entry = self.to_string();
        hash_alg.digest(log_entry.as_bytes())
    }
}

impl Display for LogEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogEntry::Event {
                domain,
                operation,
                content,
            } => {
                write!(f, "{} {} {}", domain, operation, content.0)
            }
            LogEntry::Init { hash_alg, value } => {
                let (sha, init_value) = match hash_alg {
                    HashAlgorithm::Sha256 => ("sha256", value),
                    HashAlgorithm::Sha384 => ("sha384", value),
                    HashAlgorithm::Sha512 => ("sha512", value),
                };
                write!(f, "INIT {sha}/{init_value}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attester::CompositeAttester;
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

    /// The eventlog will influence the underlying hardware
    #[ignore]
    #[tokio::test]
    async fn test_log_events() {
        let lines = Arc::new(Mutex::new(vec![]));
        let tw = TestWriter(lines.clone());
        let rtmr_extender = Arc::new(CompositeAttester::new().unwrap());
        let mut el = EventLog {
            writer: Box::new(tw),
            pcr: 17,
            rtmr_extender,
            alg: HashAlgorithm::Sha256,
        };
        let i = LogEntry::Init {
            hash_alg: HashAlgorithm::Sha256,
            value: "0000000000000000000000000000000000000000000000000000000000000000",
        };

        el.extend_entry(i, 17).await.unwrap();
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
        el.extend_entry(ev, 17).await.unwrap();
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

    #[tokio::test]
    #[serial_test::serial]
    async fn test_eventlog_from_nothing() {
        if std::path::Path::new(EVENTLOG_PATH).exists() {
            std::fs::remove_file(EVENTLOG_PATH).unwrap();
        }
        let rtmr_extender = CompositeAttester::new().unwrap();
        let mut eventlog = EventLog::new(Arc::new(rtmr_extender), HashAlgorithm::Sha256, 17)
            .await
            .unwrap();
        eventlog
            .extend_entry(
                LogEntry::Event {
                    domain: "domain",
                    operation: "operation",
                    content: "content".try_into().unwrap(),
                },
                17,
            )
            .await
            .unwrap();
        drop(eventlog);
        std::fs::remove_file(EVENTLOG_PATH).unwrap();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_eventlog_from_empty_file() {
        if !Path::new(EVENTLOG_PARENT_DIR_PATH).exists() {
            std::fs::create_dir_all(EVENTLOG_PARENT_DIR_PATH).unwrap();
        }
        let f = std::fs::File::options()
            .create(true)
            .truncate(true)
            .write(true)
            .open(EVENTLOG_PATH)
            .unwrap();
        f.sync_all().unwrap();
        drop(f);

        let rtmr_extender = Arc::new(CompositeAttester::new().unwrap());
        let mut eventlog = EventLog::new(rtmr_extender, HashAlgorithm::Sha256, 17)
            .await
            .unwrap();
        eventlog
            .extend_entry(
                LogEntry::Event {
                    domain: "domain",
                    operation: "operation",
                    content: "content".try_into().unwrap(),
                },
                17,
            )
            .await
            .unwrap();
        drop(eventlog);
        std::fs::remove_file(EVENTLOG_PATH).unwrap();
    }
}
