// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{io::Write, str::FromStr};

use anyhow::{Context, Result};
use async_trait::async_trait;
use attester::{detect_tee_type, BoxedAttester};

pub use attester::InitdataResult;

pub mod config;
pub mod token;

use log::{info, warn};
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
/// - `check_init_data`: check if the given data slice matches the current confidential
/// computing environment's host data field, e.g. MRCONFIGID for TDX, HOSTDATA for SNP.
///
/// # Example
///
/// ```no_run
/// use attestation_agent::AttestationAgent;
/// use attestation_agent::AttestationAPIs;
///
/// let mut aa = AttestationAgent::default();
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
    async fn get_token(&mut self, token_type: &str) -> Result<Vec<u8>>;

    /// Get TEE hardware signed evidence that includes the runtime data.
    async fn get_evidence(&mut self, runtime_data: &[u8]) -> Result<Vec<u8>>;

    /// Extend runtime measurement register
    async fn extend_runtime_measurement(
        &mut self,
        events: Vec<Vec<u8>>,
        register_index: Option<u64>,
    ) -> Result<()>;

    /// Check the initdata binding
    async fn check_init_data(&mut self, init_data: &[u8]) -> Result<InitdataResult>;
}

/// Attestation agent to provide attestation service.
pub struct AttestationAgent {
    _config: Config,
}

impl Default for AttestationAgent {
    /// This function would panic if a malformed `aa_kbc_param` is given
    /// either env or kernel cmdline
    fn default() -> Self {
        if let Ok(_config) = Config::try_from(config::DEFAULT_AA_CONFIG_PATH) {
            return AttestationAgent { _config };
        }

        AttestationAgent {
            _config: Config::new().expect("AA initialize"),
        }
    }
}

impl AttestationAgent {
    /// Create a new instance of [AttestationAgent].
    pub fn new(config_path: Option<&str>) -> Result<Self> {
        let _config = match config_path {
            Some(config_path) => {
                info!("Using AA config file: {config_path}");
                Config::try_from(config_path)?
            }
            None => {
                warn!("No AA config file specified. Using a default configuration.");
                Config::new()?
            }
        };

        Ok(AttestationAgent { _config })
    }

    /// This is a workaround API for initdata in CoCo. Once
    /// a better design is implemented we can deprecate the API.
    /// See https://github.com/kata-containers/kata-containers/issues/9468
    pub fn update_configuration(&mut self, conf: &str) -> Result<()> {
        let mut tmpfile = tempfile::NamedTempFile::new()?;
        let _ = tmpfile.write(conf.as_bytes())?;
        tmpfile.flush()?;

        let _config = Config::try_from(
            tmpfile
                .path()
                .as_os_str()
                .to_str()
                .expect("tempfile will not create non-unicode char"),
            // Here we can use `expect()` because tempfile crate will generate file name
            // only including numbers and alphabet (0-9, a-z, A-Z)
        )?;
        self._config = _config;
        Ok(())
    }
}

#[async_trait]
impl AttestationAPIs for AttestationAgent {
    async fn get_token(&mut self, token_type: &str) -> Result<Vec<u8>> {
        let token_type = TokenType::from_str(token_type).context("Unsupported token type")?;

        match token_type {
            #[cfg(feature = "kbs")]
            token::TokenType::Kbs => {
                token::kbs::KbsTokenGetter::new(&self._config.token_configs.kbs)
                    .get_token()
                    .await
            }
            #[cfg(feature = "coco_as")]
            token::TokenType::CoCoAS => {
                token::coco_as::CoCoASTokenGetter::new(&self._config.token_configs.coco_as)
                    .get_token()
                    .await
            }
        }
    }

    /// Get TEE hardware signed evidence that includes the runtime data.
    async fn get_evidence(&mut self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        let tee_type = detect_tee_type();
        let attester = TryInto::<BoxedAttester>::try_into(tee_type)?;
        let evidence = attester.get_evidence(runtime_data.to_vec()).await?;
        Ok(evidence.into_bytes())
    }

    /// Extend runtime measurement register
    async fn extend_runtime_measurement(
        &mut self,
        events: Vec<Vec<u8>>,
        register_index: Option<u64>,
    ) -> Result<()> {
        let tee_type = detect_tee_type();
        let attester = TryInto::<BoxedAttester>::try_into(tee_type)?;
        attester
            .extend_runtime_measurement(events, register_index)
            .await?;
        Ok(())
    }

    /// Check the initdata binding. If current platform does not support initdata
    /// injection, return `InitdataResult::Unsupported`.
    async fn check_init_data(&mut self, init_data: &[u8]) -> Result<InitdataResult> {
        let tee_type = detect_tee_type();
        let attester = TryInto::<BoxedAttester>::try_into(tee_type)?;
        attester.check_init_data(init_data).await
    }
}
