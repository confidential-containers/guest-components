// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::config::{aa_kbc_params, kbs::KbsConfig};

use super::GetToken;
use anyhow::*;
use async_trait::async_trait;
use kbs_protocol::{evidence_provider::NativeEvidenceProvider, KbsClientBuilder};
use log::warn;
use serde::Serialize;

#[derive(Serialize)]
struct Message {
    token: String,
    tee_keypair: String,
}

#[derive(Default)]
pub struct KbsTokenGetter {
    kbs_host_url: String,
    cert: Option<String>,
}

#[async_trait]
impl GetToken for KbsTokenGetter {
    async fn get_token(&self) -> Result<Vec<u8>> {
        let evidence_provider = Box::new(NativeEvidenceProvider::new()?);

        let mut builder =
            KbsClientBuilder::with_evidence_provider(evidence_provider, &self.kbs_host_url);

        if let Some(cert) = &self.cert {
            builder = builder.add_kbs_cert(cert);
        }

        let mut client = builder.build()?;

        let (token, tee_keypair) = client.get_token().await?;
        let message = Message {
            token: token.content,
            tee_keypair: tee_keypair.to_pkcs1_pem()?.to_string(),
        };

        let res = serde_json::to_vec(&message)?;
        Ok(res)
    }
}

impl KbsTokenGetter {
    pub fn new(config: &KbsConfig) -> Self {
        let kbs_host_url = match config.url.is_empty() {
            false => config.url.clone(),
            true => {
                warn!("No KBS address is provided in the config file, try legacy ways to get from `aa_kbc_params`");
                aa_kbc_params::get_params()
                    .expect("failed to get aa_kbc_params")
                    .uri()
                    .to_string()
            }
        };
        Self {
            kbs_host_url,
            cert: config.cert.clone(),
        }
    }
}
