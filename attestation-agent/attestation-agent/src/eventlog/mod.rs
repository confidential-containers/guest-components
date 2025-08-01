// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod tcg2;

use std::{
    fmt::Display,
    fs::{remove_file, File},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    sync::Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use attester::BoxedAttester;
use const_format::concatcp;

use kbs_types::HashAlgorithm;
use log::warn;

use crate::eventlog::tcg2::Tcg2EventEntry;

/// AA's eventlog will be put into this parent directory
pub const EVENTLOG_PARENT_DIR_PATH: &str = "/run/attestation-agent";

/// AA's eventlog will be stored inside the file
pub const EVENTLOG_PATH: &str = concatcp!(EVENTLOG_PARENT_DIR_PATH, "/eventlog");

/// A new log entry will be cached in this file before writing to the eventlog file.
pub const WAL_CACHE: &str = concatcp!(EVENTLOG_PARENT_DIR_PATH, "/.wal_event_entry");

pub struct EventLog {
    writer: Box<dyn Writer>,
    rtmr_extender: Arc<BoxedAttester>,
    alg: HashAlgorithm,
    pcr: u64,
}

trait Writer: Sync + Send {
    fn write(&mut self, data: &[u8]) -> Result<()>;
    fn seek(&mut self, pos: u64) -> Result<()>;
    fn current_pos(&self) -> u64;
}

pub struct FileWriter {
    file: File,
    pos: u64,
}

impl Writer for FileWriter {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.file.write(data).context("failed to write log")?;
        self.file
            .sync_data()
            .context("failed to flush log to I/O media")?;
        self.pos += data.len() as u64;
        Ok(())
    }

    fn seek(&mut self, pos: u64) -> Result<()> {
        self.file
            .seek(SeekFrom::Start(pos))
            .context("failed to seek log")?;
        self.pos = pos;
        Ok(())
    }

    fn current_pos(&self) -> u64 {
        self.pos
    }
}

/// Write Ahead Log
struct WalCache {
    /// The target PCR value after the log is written.
    expected_pcr: Vec<u8>,

    /// The event data to be written.
    event_data: String,

    /// The offset of the event data in the event log.
    event_offset: u64,
}

impl EventLog {
    pub async fn new(rtmr_extender: Arc<BoxedAttester>, pcr: u64) -> Result<Self> {
        tokio::fs::create_dir_all(EVENTLOG_PARENT_DIR_PATH)
            .await
            .context("create eventlog parent dir")?;
        let mut file = File::options()
            .append(true)
            .create(true)
            .open(EVENTLOG_PATH)
            .context("open AAEL file")?;
        let pos = file.stream_position()?;

        let mut writer = Box::new(FileWriter { file, pos });
        let alg = rtmr_extender.ccel_hash_algorithm();
        // if any WAL cache file exists, we should handle recovering from crash
        match Self::read_wal_cache(alg.digest_len()) {
            Ok(Some(wal_cache)) => {
                warn!("Recover from a previous crash.");
                let current_pcr = rtmr_extender.get_runtime_measurement(pcr).await.context("get runtime measurement")?;
                let aael_event = Event::try_from(&wal_cache.event_data[..])?;
                let (tcg2_event, tcg2_event_digest) = Into::<Tcg2EventEntry>::into(aael_event).digest(alg);
                let tcg2_event_data = tcg2_event.to_le_bytes();

                // if the PCR has not been extended yet, we should just write eventlog
                if current_pcr != wal_cache.expected_pcr {
                    let mut pcr_status = current_pcr.clone();
                    let mut tcg2_event_digest_clone = tcg2_event_digest.clone();
                    pcr_status.append(&mut tcg2_event_digest_clone);
                    let digest_to_be_updated = alg.digest(&pcr_status);

                    if digest_to_be_updated != wal_cache.expected_pcr {
                        bail!("fatal error when recovering. The eventlog file {EVENTLOG_PATH} is probably corrupted, or other process has extend the target PCR {pcr}.")
                    }

                    // else, update the PCR
                    rtmr_extender.extend_runtime_measurement(tcg2_event_digest, pcr).await?;
                }

                writer.seek(wal_cache.event_offset)?;
                writer.write(&tcg2_event_data)?;
                Self::clean_wal_cache()?;
                Ok(Self {
                    writer,
                    rtmr_extender,
                    alg,
                    pcr,
                })
            }
            Err(_) => bail!("Failed to read wal cache. This is a significant error caused by a previous crash. Please try delete `{WAL_CACHE}` and restart the attestation agent."),
            Ok(None) => Ok(Self {
                writer,
                rtmr_extender,
                alg,
                pcr,
            })
        }
    }

    /// Record the event and the target digest into cache file before write, this would do
    /// help when there is a crash between extending PCR and logging event.
    fn write_wal_cache(&self, wal_cache: WalCache) -> Result<()> {
        let mut file = File::create(WAL_CACHE)?;
        file.write_all(&wal_cache.event_offset.to_be_bytes())?;
        file.write_all(wal_cache.expected_pcr.as_ref())?;
        file.write_all(wal_cache.event_data.as_ref())?;
        file.sync_data()?;
        Ok(())
    }

    /// Remove the wal cache file.
    pub fn clean_wal_cache() -> Result<()> {
        remove_file(WAL_CACHE)?;
        Ok(())
    }

    /// Try to read the wal cache file.
    fn read_wal_cache(digest_len: usize) -> Result<Option<WalCache>> {
        if !Path::new(WAL_CACHE).exists() {
            return Ok(None);
        }
        let mut file = File::open(WAL_CACHE)?;
        let mut event_offset = [0u8; 8];
        file.read_exact(&mut event_offset)?;
        let event_offset = u64::from_le_bytes(event_offset);

        let mut expected_pcr = vec![0u8; digest_len];
        file.read_exact(&mut expected_pcr)?;

        let mut event_data = String::new();
        let _ = file.read_to_string(&mut event_data)?;

        Ok(Some(WalCache {
            expected_pcr,
            event_data,
            event_offset,
        }))
    }

    /// This an atomic operation, which will both extend the PCR and write the eventlog to disk.
    /// We should bring in a little transection mechanism (WAL, Write Ahead Log) to make sure the atomicity.
    ///
    /// The logical order:
    ///
    /// 1. write expected PCR and AAEL event data to WAL cache file on filesystem (memory backend)
    /// 2. Extend PCR
    /// 3. Write eventlog entry to AAEL file on filesystem (memory backend)
    /// 4. delete WAL cache file on filesystem (memory backend)
    ///
    /// Once kernel provides a more robust way (atomic) to maintain an eventlog,
    /// we can remove the WAL cache file mechanism.
    pub async fn extend_entry(&mut self, log_entry: Event<'_>, pcr: u64) -> Result<()> {
        let aael_event_data = log_entry.to_string();
        let rtmr = self.rtmr_extender.pcr_to_ccmr(self.pcr);
        let (tcg2_event, event_digest) = Into::<Tcg2EventEntry>::into(log_entry)
            .with_target_measurement_register(rtmr as u32)
            .digest(self.alg);

        let tcg2_event_data = tcg2_event.to_le_bytes();
        let mut current_pcr = self.rtmr_extender.get_runtime_measurement(pcr).await?;

        current_pcr.extend_from_slice(&event_digest);
        let expected_pcr = self.alg.digest(&current_pcr);

        let event_offset = self.writer.current_pos();
        let wal_cache = WalCache {
            expected_pcr,
            event_data: aael_event_data,
            event_offset,
        };
        self.write_wal_cache(wal_cache)
            .context("write wal cache file failed")?;

        self.rtmr_extender
            .extend_runtime_measurement(event_digest, pcr)
            .await?;
        self.writer
            .write(&tcg2_event_data)
            .context("write log entry")?;

        Self::clean_wal_cache().context("remove wal cache file failed")?;
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

pub struct Event<'a> {
    domain: &'a str,
    operation: &'a str,
    content: Content<'a>,
}

impl<'a> Event<'a> {
    pub fn new(domain: &'a str, operation: &'a str, content: &'a str) -> Result<Self> {
        let content = Content::try_from(content)?;
        Ok(Event {
            domain,
            operation,
            content,
        })
    }
}

impl<'a> TryFrom<&'a str> for Event<'a> {
    type Error = anyhow::Error;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let first_sp = s
            .find(' ')
            .ok_or(anyhow!("No space found in event string"))?;
        let after_first = &s[first_sp + 1..];
        let second_sp_rel = after_first
            .find(' ')
            .ok_or(anyhow!("No second space found in event string"))?;
        let second_sp = first_sp + 1 + second_sp_rel;

        let domain = &s[..first_sp];
        let operation = &s[first_sp + 1..second_sp];
        let content = &s[second_sp + 1..];
        Ok(Event {
            domain,
            operation,
            content: Content::try_from(content)?,
        })
    }
}

impl Display for Event<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.domain, self.operation, self.content.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attester::detect_tee_type;
    use rstest::rstest;
    use std::sync::{Arc, Mutex};

    struct TestWriter {
        content: Arc<Mutex<Vec<u8>>>,
        pos: u64,
    }

    impl Writer for TestWriter {
        fn write(&mut self, data: &[u8]) -> Result<()> {
            self.content.lock().unwrap().extend_from_slice(data);
            Ok(())
        }

        fn seek(&mut self, pos: u64) -> Result<()> {
            self.pos = pos;
            Ok(())
        }

        fn current_pos(&self) -> u64 {
            self.pos
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
    #[serial_test::serial]
    async fn test_log_events() {
        std::fs::create_dir_all(EVENTLOG_PARENT_DIR_PATH).unwrap();
        let lines = Arc::new(Mutex::new(vec![]));
        let tw = TestWriter {
            content: lines.clone(),
            pos: 0,
        };
        let tee = detect_tee_type();
        let rtmr_extender =
            BoxedAttester::try_from(tee).expect("Failed to create BoxedAttester from Tee type");

        let mut el = EventLog {
            writer: Box::new(tw),
            pcr: 17,
            rtmr_extender: Arc::new(rtmr_extender),
            alg: HashAlgorithm::Sha384,
        };

        el.extend_entry(
            Event {
                domain: "domain",
                operation: "operation",
                content: "content1".try_into().unwrap(),
            },
            17,
        )
        .await
        .unwrap();
        el.extend_entry(
            Event {
                domain: "domain",
                operation: "operation",
                content: "content2".try_into().unwrap(),
            },
            17,
        )
        .await
        .unwrap();

        let expected = tokio::fs::read("./test/aael.bin").await.unwrap();
        assert_eq!(expected, lines.lock().unwrap().to_vec());
    }

    #[rstest]
    #[case(
        "domain",
        "operation",
        "content",
        "46df8dacf00a07d34a83cdf56d7978697790787cf2ba1432ef7c38f22cd96351",
        HashAlgorithm::Sha256
    )]
    #[case("domain", "operation", "content", "dad5f0e226318ffa9839b75a472c6aa7fdb5834949d0a0a22990cf04d5692440fb00f3aa0609db7e49cd8d793f670d02", HashAlgorithm::Sha384)]
    #[case("domain", "operation", "content", "b708d222ca8bd44dfe6ba0c4ca2cbb72379276fba8091025217064be45a813e5d6124ccf073219edb617d1faf007d55061465bdf34b7437dbdc9a7405bd4e9c0", HashAlgorithm::Sha512)]
    fn test_event_digest(
        #[case] domain: &str,
        #[case] operation: &str,
        #[case] content: &str,
        #[case] digest: &str,
        #[case] hash_alg: HashAlgorithm,
    ) {
        let event = Event {
            domain,
            operation,
            content: content.try_into().unwrap(),
        };

        let (_, dig) = Into::<Tcg2EventEntry>::into(event).digest(hash_alg);
        let dig_hex = dig.iter().map(|c| format!("{c:02x}")).collect::<String>();
        assert_eq!(dig_hex, digest);
    }

    // skip this test because it will depend/influence the underlying hardware
    #[ignore]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_eventlog_from_nothing() {
        if std::path::Path::new(EVENTLOG_PATH).exists() {
            std::fs::remove_file(EVENTLOG_PATH).unwrap();
        }
        let tee = detect_tee_type();
        let rtmr_extender =
            BoxedAttester::try_from(tee).expect("Failed to create BoxedAttester from Tee type");
        let mut eventlog = EventLog::new(Arc::new(rtmr_extender), 17).await.unwrap();
        eventlog
            .extend_entry(
                Event {
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

    // skip this test because it will depend/influence the underlying hardware
    #[ignore]
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

        let tee = detect_tee_type();
        let rtmr_extender =
            BoxedAttester::try_from(tee).expect("Failed to create BoxedAttester from Tee type");
        let mut eventlog = EventLog::new(Arc::new(rtmr_extender), 17).await.unwrap();
        eventlog
            .extend_entry(
                Event {
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
