// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::str::FromStr;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use attester::{detect_tee_type, BoxedAttester};

pub use attester::InitdataResult;

pub mod config;
mod token;

use token::*;

use crate::config::{aa_kbc_params, Config};

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
    config: Option<Config>,
}

impl Default for AttestationAgent {
    fn default() -> Self {
        let config = Config::try_from(config::DEFAULT_AA_CONFIG_PATH).ok();
        AttestationAgent { config }
    }
}

impl AttestationAgent {
    /// Create a new instance of [AttestationAgent].
    pub fn new(config_path: &str) -> Self {
        let config = Config::try_from(config_path).ok();

        AttestationAgent { config }
    }
}

#[async_trait]
impl AttestationAPIs for AttestationAgent {
    async fn get_token(&mut self, token_type: &str) -> Result<Vec<u8>> {
        let _uri = match self.config.as_ref() {
            Some(c) => c.as_uri.clone(),
            None => {
                let params = aa_kbc_params::get_params()
                    .await
                    .map_err(|_| anyhow!("Get AS URI failed"))?;
                params.uri().to_string()
            }
        };

        match TokenType::from_str(token_type).map_err(|e| anyhow!("Unsupported token type: {e}"))? {
            #[cfg(feature = "kbs")]
            token::TokenType::Kbs => token::kbs::KbsTokenGetter::default().get_token(_uri).await,
            #[cfg(feature = "coco_as")]
            token::TokenType::CoCoAS => {
                token::coco_as::CoCoASTokenGetter::default()
                    .get_token(_uri)
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
