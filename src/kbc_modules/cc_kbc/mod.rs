// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::kbc_modules::{KbcCheckInfo, KbcInterface};

mod attester;
mod crypto;
mod kbs_protocol;

use anyhow::*;
use async_trait::async_trait;
use attester::{detect_tee_type, Attester};
use crypto::{hash_chunks, TeeKey};
use kbs_protocol::message::*;

pub struct Kbc {
    tee: String,
    token: Option<String>,
    nonce: String,
    tee_key: Option<TeeKey>,
    attester: Option<Box<dyn Attester + Send + Sync>>,
}

#[async_trait]
impl KbcInterface for Kbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Err(anyhow!("Check API of this KBC is unimplemented."))
    }

    async fn decrypt_payload(&mut self, _annotation: &str) -> Result<Vec<u8>> {
        Err(anyhow!("Decrypt Payload API of this KBC is unimplemented."))
    }

    async fn get_resource(&mut self, _description: String) -> Result<Vec<u8>> {
        Err(anyhow!("Unimplemented"))
    }
}

impl Kbc {
    pub fn new(_kbs_uri: String) -> Kbc {
        // Detect TEE type of the current platform.
        let tee_type = detect_tee_type();

        // Create attester instance.
        let attester = tee_type.to_attester().ok();

        Kbc {
            tee: tee_type.to_string(),
            token: None,
            nonce: String::default(),
            tee_key: TeeKey::new().ok(),
            attester,
        }
    }

    fn generate_evidence(&self) -> Result<Evidence> {
        let key = self
            .tee_key
            .as_ref()
            .ok_or_else(|| anyhow!("Generate TEE key failed"))?;
        let attester = self
            .attester
            .as_ref()
            .ok_or_else(|| anyhow!("TEE attester missed"))?;

        let tee_pubkey = key
            .export_pubkey()
            .map_err(|e| anyhow!("Export TEE pubkey failed: {:?}", e))?;
        let tee_pubkey_string = serde_json::to_string(&tee_pubkey)?;

        let ehd_chunks = vec![
            self.nonce.clone().into_bytes(),
            tee_pubkey_string.clone().into_bytes(),
        ];

        let ehd = hash_chunks(ehd_chunks);

        let tee_evidence = attester
            .get_evidence(ehd)
            .map_err(|e| anyhow!("Get TEE evidence failed: {:?}", e))?;

        Ok(Evidence {
            nonce: self.nonce.clone(),
            tee: self.tee.clone(),
            tee_pubkey: tee_pubkey_string,
            tee_evidence,
        })
    }

    fn decrypt_response_output(&self, response: Response) -> Result<Vec<u8>> {
        let key = self
            .tee_key
            .clone()
            .ok_or_else(|| anyhow!("TEE rsa key missing"))?;
        response.decrypt_output(key)
    }
}
