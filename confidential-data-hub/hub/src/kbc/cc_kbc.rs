// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Context, Result};
use async_trait::async_trait;
use kbs_protocol::{
    client::KbsClient as KbsProtocolClient,
    token_provider::{AATokenProvider, TokenProvider},
    KbsClientCapabilities, ResourceUri,
};
use tracing::{info, warn};

use super::Kbc;

pub struct CcKbc {
    client: KbsProtocolClient<Box<dyn TokenProvider>>,
}

impl CcKbc {
    pub async fn new(
        kbs_host_url: &str,
        kbs_cert: Option<&String>,
        aa_socket: &str,
    ) -> Result<Self> {
        let token_provider = AATokenProvider::new_with_socket(aa_socket)
            .await
            .context("create AA token provider failed")?;
        let client = kbs_protocol::KbsClientBuilder::with_token_provider(
            Box::new(token_provider),
            kbs_host_url,
        );

        let client = match kbs_cert {
            Some(cert_pem) => {
                info!("Use KBS public key cert");
                client.add_kbs_cert(cert_pem)
            }
            None => {
                warn!("Use no KBS public key certs.");
                client
            }
        };

        let client = client.build().context("cc-kbc create kbc client failed")?;
        Ok(Self { client })
    }
}

#[async_trait]
impl Kbc for CcKbc {
    async fn get_resource(&mut self, rid: ResourceUri) -> Result<Vec<u8>> {
        let secret = self
            .client
            .get_resource(rid)
            .await
            .context("get resource failed")?;
        Ok(secret)
    }
}
