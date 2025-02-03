// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use attester::{detect_tee_types, BoxedAttester};
use kbs_types::Tee;
use std::{str::FromStr, sync::Arc};
use tokio::sync::{Mutex, RwLock};

pub use attester::InitDataResult;

pub mod config;
mod eventlog;
pub mod token;

use eventlog::{Content, EventLog, LogEntry};
use log::{debug, info, warn};
use token::*;

use crate::config::Config;

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

    /// Get TEE hardware signed evidence that includes the runtime data.
    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<String>;

    /// Extend runtime measurement register
    async fn extend_runtime_measurement(
        &self,
        domain: &str,
        operation: &str,
        content: &str,
        register_index: Option<u64>,
    ) -> Result<()>;

    /// Bind initdata
    async fn bind_init_data(&self, init_data: &[u8]) -> Result<InitDataResult>;

    fn get_tee_types(&self) -> Vec<Tee>;
}

/// Attestation agent to provide attestation service.
pub struct AttestationAgent {
    config: RwLock<Config>,
    attesters: Vec<(Tee, Arc<BoxedAttester>)>,
    eventlog: Option<Mutex<EventLog>>,
    tees: Vec<Tee>,
}

impl AttestationAgent {
    pub async fn init(&mut self) -> Result<()> {
        let config = self.config.read().await;

        if config.eventlog_config.enable_eventlog {
            // Identify one attester to use with the EventLog.
            // Only one attester is expected to support runtime measurements.
            let runtime_attester = {
                let mut runtime_attester = None;
                for (tee, attester) in &self.attesters {
                    if attester.supports_runtime_measurement() {
                        info!("Found {:?} for runtime attestation.", tee);
                        if let Some(_already_found_attester) = runtime_attester {
                            bail!("Only one attester should support runtime attestation")
                        }
                        runtime_attester = Some(attester.clone());
                    }
                }
                runtime_attester.ok_or(anyhow!("No runtime attester found."))?
            };

            let eventlog = EventLog::new(
                runtime_attester,
                config.eventlog_config.eventlog_algorithm,
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
                warn!("No AA config file specified. Using a default configuration.");
                Config::new()?
            }
        };
        let config = RwLock::new(config);

        let mut attesters = vec![];
        let tees = detect_tee_types();

        for tee in &tees {
            attesters.push((*tee, Arc::new(BoxedAttester::try_from(*tee)?)));
        }

        Ok(AttestationAgent {
            config,
            attesters,
            eventlog: None,
            tees,
        })
    }
}

#[async_trait]
impl AttestationAPIs for AttestationAgent {
    async fn get_token(&self, token_type: &str) -> Result<Vec<u8>> {
        let token_type = TokenType::from_str(token_type).context("Unsupported token type")?;

        match token_type {
            #[cfg(feature = "kbs")]
            token::TokenType::Kbs => {
                token::kbs::KbsTokenGetter::new(&self.config.read().await.token_configs.kbs)
                    .get_token()
                    .await
            }
            #[cfg(feature = "coco_as")]
            token::TokenType::CoCoAS => {
                token::coco_as::CoCoASTokenGetter::new(
                    &self.config.read().await.token_configs.coco_as,
                )
                .get_token()
                .await
            }
        }
    }

    /// Get TEE hardware signed evidence that includes the runtime data.
    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<String> {
        let mut evidence: Vec<(Tee, String)> = vec![];
        for (tee, attester) in &self.attesters {
            let ev = attester.get_evidence(runtime_data.to_vec()).await?;
            evidence.push((*tee, ev));
        }

        Ok(serde_json::to_string(&evidence)?)
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
    ) -> Result<()> {
        let Some(ref eventlog) = self.eventlog else {
            bail!("Extend eventlog not enabled when launching!");
        };

        let (pcr, log_entry) = {
            let config = self.config.read().await;

            let pcr = register_index.unwrap_or_else(|| {
                let pcr = config.eventlog_config.init_pcr;
                debug!("No PCR index provided, use default {pcr}");
                pcr
            });

            let content: Content = content.try_into()?;

            let log_entry = LogEntry::Event {
                domain,
                operation,
                content,
            };

            (pcr, log_entry)
        };

        eventlog.lock().await.extend_entry(log_entry, pcr).await?;

        Ok(())
    }

    /// Perform the initdata binding. If current platform does not support initdata
    /// binding, return `InitdataResult::Unsupported`.
    async fn bind_init_data(&self, init_data: &[u8]) -> Result<InitDataResult> {
        let mut init_data_result = InitDataResult::Unsupported;

        for (tee, attester) in &self.attesters {
            match attester.bind_init_data(init_data).await? {
                InitDataResult::Ok => init_data_result = InitDataResult::Ok,
                _ => info!("Unable to bind init-data for {:?}", tee),
            };
        }
        Ok(init_data_result)
    }

    /// Get the tee type of current platform. If no platform is detected,
    /// `Sample` will be returned.
    fn get_tee_types(&self) -> Vec<Tee> {
        self.tees.clone()
    }
}
