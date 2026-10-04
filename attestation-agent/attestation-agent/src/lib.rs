// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use attester::{BoxedAttester, detect_attestable_devices, detect_tee_type};
use kbs_types::{HashAlgorithm, Tee};
use std::{collections::HashMap, str::FromStr, sync::Arc};
use tokio::sync::{Mutex, RwLock};

pub use attester::InitDataResult;

pub mod config;
mod eventlog;
pub mod initdata;

#[allow(unreachable_code)]
pub mod token;

use eventlog::EventLog;
use token::*;
use tracing::{debug, info};

use crate::{config::Config, eventlog::Event};

const INITDATA_EVENT_DOMAIN: &str = "github.com/confidential-containers";
const INITDATA_EVENT_OPERATION: &str = "InitData";

pub enum RuntimeMeasurement {
    /// The runtime measurement is extended successfully.
    Ok,

    /// The runtime measurement is not supported by the attester.
    NotSupported,

    /// The runtime measurement is not enabled by the attestation agent configuration.
    NotEnabled,
}

/// Attestation Agent (AA for short) is a rust library crate for attestation procedure
/// in confidential containers. It provides kinds of service APIs related to attestation,
/// including the following
/// - `get_token`: get attestation token from remote services, e.g. attestation services.
/// - `get_evidence`: get hardware TEE signed evidence due to given runtime_data, s.t.
/// report data.
/// - `extend_runtime_measurement`: extend the runtime measurement. This will extend the
/// current hardware runtime measurement register (if any) or PCR for (v)TPM (under
/// development) platforms
/// with a runtime event.
/// - `bind_init_data`: bind the given data slice to the current confidential
/// computing environment. This can be a verify operation or an extension of the TEE
/// evidence
///
/// # Example
///
/// ```no_run
/// use attestation_agent::AttestationAgent;
/// use attestation_agent::AttestationAPIs;
/// use attestation_agent::config::Config;
///
/// // initialize with empty config
/// let mut aa = AttestationAgent::new(Config::default()).unwrap();
///
/// let _quote = aa.get_evidence(&[0;64]);
/// ```
/// `AttestationAPIs` defines the service APIs of attestation agent that need to make requests
///  to the Relying Party (Key Broker Service) in Confidential Containers.
#[async_trait]
pub trait AttestationAPIs {
    /// Get attestation Token
    async fn get_token(&self, token_type: &str) -> Result<Vec<u8>>;

    /// Get TEE hardware evidence from the primary attester with runtime
    /// data included.
    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>>;

    /// Get TEE hardware evidence from all additional attesters with runtime data
    /// included. If no additional attester is configured, it will return an empty vector.
    async fn get_additional_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>>;

    /// Extend runtime measurement register
    async fn extend_runtime_measurement(
        &self,
        domain: &str,
        operation: &str,
        content: &str,
        register_index: Option<u64>,
    ) -> Result<RuntimeMeasurement>;

    /// Bind initdata
    async fn bind_init_data(&self, init_data: &[u8]) -> Result<InitDataResult>;

    fn get_tee_type(&self) -> Tee;

    fn get_additional_tees(&self) -> Vec<Tee>;
}

/// Attestation agent to provide attestation service.
pub struct AttestationAgent {
    primary_tee: Tee,
    config: RwLock<Config>,
    eventlog: Option<Mutex<EventLog>>,
    initdata: Option<String>,
    primary_attester: Arc<BoxedAttester>,
    additional_attesters: HashMap<Tee, BoxedAttester>,
}

impl AttestationAgent {
    pub async fn init(&mut self) -> Result<()> {
        let config = self.config.read().await;
        if config.eventlog_config.enable_eventlog {
            let eventlog = EventLog::new(self.primary_attester.clone()).await?;

            self.eventlog = Some(Mutex::new(eventlog));
        }

        Ok(())
    }

    /// Bind initdata like [`AttestationAPIs::bind_init_data`], but when the platform register
    /// for it is unset, record the digest as an `InitData` event in the eventlog's default
    /// register (RTMR3 on TDX) instead. This runs whether or not the eventlog is enabled, and
    /// fails rather than leaving initdata unbound.
    pub async fn bind_or_record_init_data(
        &self,
        alg: HashAlgorithm,
        digest: &[u8],
    ) -> Result<InitDataResult> {
        match self.primary_attester.bind_init_data(digest).await? {
            InitDataResult::NotBound => {
                if !self.primary_attester.supports_runtime_measurement() {
                    bail!("initdata is not bound and this platform cannot extend RTMR3");
                }
                let pcr = self.config.read().await.eventlog_config.init_pcr;
                let extended = match &self.eventlog {
                    Some(eventlog) => {
                        record_init_data(&mut *eventlog.lock().await, pcr, alg, digest).await?
                    }
                    // The eventlog is off for runtime events, but initdata still has to be
                    // measured, so open it just for this.
                    None => {
                        let mut eventlog = EventLog::new(self.primary_attester.clone()).await?;
                        record_init_data(&mut eventlog, pcr, alg, digest).await?
                    }
                };
                info!("Initdata recorded in the eventlog (extended: {extended}).");
                Ok(InitDataResult::Ok)
            }
            result => Ok(result),
        }
    }

    /// Create a new instance of [AttestationAgent].
    pub fn new(config: Config) -> Result<Self> {
        let config = RwLock::new(config);

        let primary_tee = detect_tee_type();
        let additional_tees = detect_attestable_devices();

        let mut additional_attesters = HashMap::new();
        for tee in additional_tees {
            additional_attesters.insert(tee, tee.try_into()?);
        }

        Ok(AttestationAgent {
            primary_tee,
            config,
            eventlog: None,
            initdata: None,
            additional_attesters,
            primary_attester: Arc::new(primary_tee.try_into()?),
        })
    }

    /// Set initdata toml as status of current AA instance.
    pub fn set_initdata_toml(&mut self, initdata_toml: String) {
        self.initdata = Some(initdata_toml);
    }
}

#[async_trait]
impl AttestationAPIs for AttestationAgent {
    async fn get_token(&self, token_type: &str) -> Result<Vec<u8>> {
        let token_type = TokenType::from_str(token_type).context("Unsupported token type")?;

        match token_type {
            #[cfg(feature = "kbs")]
            token::TokenType::Kbs => {
                token::kbs::KbsTokenGetter::new(
                    self.config
                        .read()
                        .await
                        .token_configs
                        .kbs
                        .as_ref()
                        .ok_or(anyhow::anyhow!(
                            "kbs token config not configured in config file"
                        ))?,
                )
                .get_token(self.initdata.as_deref())
                .await
            }
            // TODO: add initdata plaintext for CoCoAS token
            #[cfg(feature = "coco_as")]
            token::TokenType::CoCoAS => {
                token::coco_as::CoCoASTokenGetter::new(
                    self.config
                        .read()
                        .await
                        .token_configs
                        .coco_as
                        .as_ref()
                        .ok_or(anyhow::anyhow!(
                            "coco_as token config not configured in config file"
                        ))?,
                )
                .get_token()
                .await
            }
        }
    }

    /// Get TEE hardware evidence from the primary attester with runtime
    /// data included.
    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        let evidence = self
            .primary_attester
            .get_evidence(runtime_data.to_vec())
            .await?;
        Ok(evidence.to_string().into_bytes())
    }

    /// Get TEE hardware evidence from all additional attesters with runtime data
    /// included.
    async fn get_additional_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        let mut evidence = HashMap::new();

        for (tee, attester) in &self.additional_attesters {
            evidence.insert(*tee, attester.get_evidence(runtime_data.to_vec()).await?);
        }

        if evidence.is_empty() {
            info!("No additional attesters configured, returning empty evidence.");
            return Ok(vec![]);
        }

        let evidence: Vec<u8> =
            serde_json::to_vec(&evidence).context("Failed to serialize additional evidence")?;
        Ok(evidence)
    }

    /// Extend runtime measurement register. Parameters
    /// - `events`: a event slice. Any single event will be calculated into a hash digest to extend the current
    /// platform's RTMR.
    /// - `register_index`: a target PCR that will be used to extend RTMR. Note that different platform
    /// would have its own strategy to map a PCR index into an architectural RTMR index. If not given, a default one
    /// will be used.
    async fn extend_runtime_measurement(
        &self,
        domain: &str,
        operation: &str,
        content: &str,
        register_index: Option<u64>,
    ) -> Result<RuntimeMeasurement> {
        let Some(ref eventlog) = self.eventlog else {
            return Ok(RuntimeMeasurement::NotEnabled);
        };

        if !self.primary_attester.supports_runtime_measurement() {
            return Ok(RuntimeMeasurement::NotSupported);
        }

        let (pcr, log_entry) = {
            let config = self.config.read().await;

            let pcr = register_index.unwrap_or_else(|| {
                let pcr = config.eventlog_config.init_pcr;
                debug!("No PCR index provided, use default {pcr}");
                pcr
            });

            let log_entry = Event::new(domain, operation, content)?;

            (pcr, log_entry)
        };

        eventlog.lock().await.extend_entry(log_entry, pcr).await?;

        Ok(RuntimeMeasurement::Ok)
    }

    /// Perform the initdata binding. If current platform does not support initdata
    /// binding, return `InitdataResult::Unsupported`.
    async fn bind_init_data(&self, init_data: &[u8]) -> Result<InitDataResult> {
        match self.primary_attester.bind_init_data(init_data).await? {
            InitDataResult::NotBound => {
                bail!(
                    "initdata is not bound: the platform register for it is unset, pass the initdata TOML so AA can record it"
                )
            }
            result => Ok(result),
        }
    }

    /// Get the tee type of current platform. If no platform is detected,
    /// `Sample` will be returned.
    fn get_tee_type(&self) -> Tee {
        self.primary_tee
    }

    fn get_additional_tees(&self) -> Vec<Tee> {
        self.additional_attesters.keys().cloned().collect()
    }
}

/// Log and measure the initdata digest once per boot. Returns false when an earlier AA run
/// already recorded the same digest; a different recorded digest is an error.
async fn record_init_data(
    eventlog: &mut EventLog,
    pcr: u64,
    alg: HashAlgorithm,
    digest: &[u8],
) -> Result<bool> {
    // Canonical JSON (RFC 8785), as the CoCo eventlog spec requires for event content.
    let content = format!(r#"{{"digest":"{alg}:{}"}}"#, hex::encode(digest));
    match eventlog
        .logged_contents(INITDATA_EVENT_DOMAIN, INITDATA_EVENT_OPERATION)?
        .as_slice()
    {
        [] => {
            let event = Event::new(INITDATA_EVENT_DOMAIN, INITDATA_EVENT_OPERATION, &content)?;
            eventlog.extend_entry(event, pcr).await?;
            Ok(true)
        }
        [logged] if *logged == content => Ok(false),
        logged => bail!("eventlog already records initdata {logged:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attester::test_utils::FakeTdx;
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::Mutex as StdMutex;

    type Registers = Arc<StdMutex<HashMap<u64, Vec<u8>>>>;

    const PCR: u64 = 17;

    /// Open the eventlog in `dir` the way a fresh AA process would, sharing `registers`
    /// so they outlive the instance like real RTMRs across an AA restart.
    async fn open(dir: &Path, registers: &Registers, crash_after_extend: bool) -> Result<EventLog> {
        let fake = FakeTdx {
            registers: registers.clone(),
            crash_after_extend,
        };
        let attester: BoxedAttester = Box::new(fake);
        EventLog::open(Arc::new(attester), &dir.join("eventlog"), dir.join("wal")).await
    }

    async fn record(dir: &Path, registers: &Registers, digest: &[u8]) -> Result<bool> {
        let mut eventlog = open(dir, registers, false).await?;
        record_init_data(&mut eventlog, PCR, HashAlgorithm::Sha384, digest).await
    }

    fn rtmr3(registers: &Registers) -> Option<Vec<u8>> {
        registers.lock().unwrap().get(&PCR).cloned()
    }

    #[tokio::test]
    async fn test_record_init_data_once_across_restarts() {
        let tmp = tempfile::tempdir().unwrap();
        let registers = Registers::default();

        assert!(record(tmp.path(), &registers, &[1; 48]).await.unwrap());
        let after_first = rtmr3(&registers).expect("RTMR3 extended");

        assert!(!record(tmp.path(), &registers, &[1; 48]).await.unwrap());
        assert_eq!(rtmr3(&registers).unwrap(), after_first);

        let eventlog = open(tmp.path(), &registers, false).await.unwrap();
        let logged = eventlog
            .logged_contents(INITDATA_EVENT_DOMAIN, INITDATA_EVENT_OPERATION)
            .unwrap();
        assert_eq!(
            logged,
            [format!(r#"{{"digest":"sha384:{}"}}"#, "01".repeat(48))]
        );
    }

    #[tokio::test]
    async fn test_record_init_data_rejects_a_different_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let registers = Registers::default();

        record(tmp.path(), &registers, &[1; 48]).await.unwrap();
        let after_first = rtmr3(&registers);

        assert!(record(tmp.path(), &registers, &[2; 48]).await.is_err());
        assert_eq!(rtmr3(&registers), after_first);
    }

    #[tokio::test]
    async fn test_record_init_data_rejects_a_malformed_log() {
        let tmp = tempfile::tempdir().unwrap();
        let registers = Registers::default();
        std::fs::write(tmp.path().join("eventlog"), b"junk").unwrap();

        assert!(record(tmp.path(), &registers, &[1; 48]).await.is_err());
        assert_eq!(rtmr3(&registers), None);
    }

    #[tokio::test]
    async fn test_record_init_data_after_a_crash_recovers_first() {
        let tmp = tempfile::tempdir().unwrap();
        let registers = Registers::default();

        // Crash after the extend lands but before the entry is written.
        let mut eventlog = open(tmp.path(), &registers, true).await.unwrap();
        let crashed = record_init_data(&mut eventlog, PCR, HashAlgorithm::Sha384, &[1; 48]).await;
        assert!(crashed.is_err());
        drop(eventlog);
        let after_crash = rtmr3(&registers).expect("RTMR3 extended before the crash");

        // WAL recovery writes the entry, so the restart finds it and does not extend again.
        assert!(!record(tmp.path(), &registers, &[1; 48]).await.unwrap());
        assert_eq!(rtmr3(&registers).unwrap(), after_crash);
    }
}
