// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[allow(unused_imports)]
#[macro_use]
extern crate strum;

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use attester::{detect_tee_type, BoxedAttester};

mod config;

use token::GetToken;

/// Attestation Agent (AA for short) is a rust library crate for attestation procedure
/// in confidential containers. It provides kinds of service APIs that need to get attestation
/// evidence or make requests to the Attestation Service in Confidential Containers.
///
/// # Example
///
/// ```rust
/// use attestation_agent::AttestationAgent;
/// use attestation_agent::AttestationAPIs;
///
/// let mut aa = AttestationAgent::new();
///
/// let key_result = aa.get_token("kbs");
/// ```
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
}

/// Attestation agent to provide attestation service.
#[derive(Default)]
pub struct AttestationAgent {}

impl AttestationAgent {
    /// Create a new instance of AttestationAgent.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AttestationAPIs for AttestationAgent {
    async fn get_token(&mut self, _token_type: &str) -> Result<Vec<u8>> {
        let token = match _token_type {
            #[cfg(feature = "kbs")]
            "kbs" => {
                let kbs_host_url = config::get_host_url().await?;
                let kbs_token = token::kbs::KbsTokenGetter::default()
                    .get_attestation_token(kbs_host_url)
                    .await?;
                kbs_token
            }
            typ => bail!("Unsupported token type {typ}"),
        };

        Ok(token)
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
}
