// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use attester::{detect_tee_type, BoxedAttester};
use kbs_types::Tee;
use std::{io::Write, str::FromStr};
use tokio::sync::{Mutex, RwLock};

pub use attester::InitdataResult;

pub mod config;
mod eventlog;
pub mod token;

use eventlog::{Content, EventLog, LogEntry};
use log::{debug, info, warn, error};
use token::*;

use crate::config::Config;

#[async_trait]
pub trait AttestationAPIs {
    async fn get_token(&self, token_type: &str) -> Result<Vec<u8>>;

    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>>;

    async fn extend_runtime_measurement(
        &self,
        domain: &str,
        operation: &str,
        content: &str,
        register_index: Option<u64>,
    ) -> Result<()>;

    async fn check_init_data(&self, init_data: &[u8]) -> Result<InitdataResult>;

    fn get_tee_type(&self) -> Tee;
}

/// Attestation agent to provide attestation service.
pub struct AttestationAgent {
    config: RwLock<Config>,
    attester: BoxedAttester,
    eventlog: Option<Mutex<EventLog>>,
    tee: Tee,
}

impl AttestationAgent {
    pub async fn init(&mut self) -> Result<()> {
        info!("Initializing AttestationAgent...");

        let config = self.config.read().await;
        debug!("Configuration loaded: {:?}", config);

        if config.eventlog_config.enable_eventlog {
            info!("Event log is enabled, initializing...");
            let alg = config.eventlog_config.eventlog_algorithm;
            let pcr = config.eventlog_config.init_pcr;

            let init_entry = LogEntry::Init(alg);
            let digest = init_entry.digest_with(alg);
            let mut eventlog = EventLog::new().context("Failed to initialize event log")?;
            eventlog.write_log(&init_entry).context("Failed to write INIT log")?;

            self.attester
                .extend_runtime_measurement(digest, pcr)
                .await
                .context("Failed to extend runtime measurement with INIT entry")?;

            self.eventlog = Some(Mutex::new(eventlog));
            debug!("Event log initialized successfully.");
        } else {
            warn!("Event log is disabled.");
        }

        info!("AttestationAgent initialization completed.");
        Ok(())
    }

    pub fn new(config_path: Option<&str>) -> Result<Self> {
        info!("Creating new AttestationAgent instance...");

        let config = match config_path {
            Some(config_path) => {
                info!("Using AA config file: {config_path}");
                Config::try_from(config_path).context("Failed to load configuration from file")?
            }
            None => {
                warn!("No config file specified, using default configuration.");
                Config::new().context("Failed to create default configuration")?
            }
        };
        let config = RwLock::new(config);

        let tee = detect_tee_type();
        info!("Detected TEE type: {:?}", tee);

        let attester: BoxedAttester = tee.try_into().context("Failed to create attester")?;

        Ok(AttestationAgent {
            config,
            attester,
            eventlog: None,
            tee,
        })
    }

    pub async fn update_configuration(&self, conf: &str) -> Result<()> {
        info!("Updating configuration...");
        let mut tmpfile = tempfile::NamedTempFile::new().context("Failed to create temp file")?;
        let _ = tmpfile.write(conf.as_bytes()).context("Failed to write to temp file")?;
        tmpfile.flush().context("Failed to flush temp file")?;

        let config = Config::try_from(
            tmpfile
                .path()
                .as_os_str()
                .to_str()
                .expect("Tempfile name should be valid UTF-8"),
        )
        .context("Failed to load configuration from temp file")?;

        *(self.config.write().await) = config;
        info!("Configuration updated successfully.");
        Ok(())
    }
}

#[async_trait]
impl AttestationAPIs for AttestationAgent {
    async fn get_token(&self, token_type: &str) -> Result<Vec<u8>> {
        debug!("Getting token for type: {}", token_type);
        let token_type = TokenType::from_str(token_type).context("Unsupported token type")?;

        match token_type {
            #[cfg(feature = "kbs")]
            token::TokenType::Kbs => {
                info!("Getting KBS token...");
                token::kbs::KbsTokenGetter::new(&self.config.read().await.token_configs.kbs)
                    .get_token()
                    .await
                    .context("Failed to get KBS token")
            }
            #[cfg(feature = "coco_as")]
            token::TokenType::CoCoAS => {
                info!("Getting CoCoAS token...");
                token::coco_as::CoCoASTokenGetter::new(
                    &self.config.read().await.token_configs.coco_as,
                )
                .get_token()
                .await
                .context("Failed to get CoCoAS token")
            }
        }
    }

    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        info!("Getting evidence...");
        let evidence = self
            .attester
            .get_evidence(runtime_data.to_vec())
            .await
            .context("Failed to get evidence")?;
        Ok(evidence.into_bytes())
    }

    async fn extend_runtime_measurement(
        &self,
        domain: &str,
        operation: &str,
        content: &str,
        register_index: Option<u64>,
    ) -> Result<()> {
        info!("Extending runtime measurement for domain: {}, operation: {}", domain, operation);

        let Some(ref eventlog) = self.eventlog else {
            bail!("Extend eventlog not enabled!");
        };

        let (pcr, log_entry, alg) = {
            let config = self.config.read().await;

            let pcr = register_index.unwrap_or_else(|| {
                let pcr = config.eventlog_config.init_pcr;
                debug!("No PCR index provided, using default: {}", pcr);
                pcr
            });

            let content: Content = content.try_into().context("Failed to parse content")?;

            let log_entry = LogEntry::Event {
                domain,
                operation,
                content,
            };
            let alg = config.eventlog_config.eventlog_algorithm;

            (pcr, log_entry, alg)
        };

        let digest = log_entry.digest_with(alg);
        {
            let mut eventlog = eventlog.lock().await;
            self.attester
                .extend_runtime_measurement(digest, pcr)
                .await
                .context("Failed to extend runtime measurement")?;

            eventlog.write_log(&log_entry).context("Failed to write log entry")?;
        }

        info!("Runtime measurement extended successfully.");
        Ok(())
    }

    async fn check_init_data(&self, init_data: &[u8]) -> Result<InitdataResult> {
        info!("Checking init data...");
        let result = self
            .attester
            .check_init_data(init_data)
            .await
            .context("Failed to check init data")?;
        Ok(result)
    }

    fn get_tee_type(&self) -> Tee {
        self.tee
    }
}

