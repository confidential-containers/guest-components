// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Context, Result};
use async_trait::async_trait;
use attester::{detect_attestable_devices, detect_tee_type, BoxedAttester};
use kbs_types::Tee;
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
use tracing::{debug, info, warn};

use crate::{config::Config, eventlog::Event};

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
///
/// // initialize with empty config
/// let mut aa = AttestationAgent::new(None).unwrap();
///
/// let _quote = aa.get_evidence(&[0;64]);
/// ```
/// `AttestationAPIs` defines the service APIs of attestation agent that need to make requests
///  to the Relying Party (Key Broker Service) in Confidential Containers.
///
/// For every service API, the `kbc_name` and `kbs_uri` is necessary, `kbc_name` tells
/// attestation agent which KBC module it should use and `kbs_uri` specifies the KBS address.
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
            let eventlog = EventLog::new(
                self.primary_attester.clone(),
                config.eventlog_config.init_pcr,
            )
            .await?;

            self.eventlog = Some(Mutex::new(eventlog));
        }

        Ok(())
    }

    /// Create a new instance of [AttestationAgent].
    pub fn new(config_path: Option<&str>) -> Result<Self> {
        let config = match config_path {
            Some(config_path) => {
                info!("Using AA config file: {config_path}");
                Config::try_from(config_path)?
            }
            None => {
                warn!("No AA config file specified. Using a default configuration and the kbs address will be read from kernel cmdline.");
                Config::default_with_kernel_cmdline()
            }
        };
        debug!("Using config: {config:#?}");
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
    /// would have its own strategy to map a PCR index into a architectual RTMR index. If not given, a default one
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
        self.primary_attester.bind_init_data(init_data).await
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
