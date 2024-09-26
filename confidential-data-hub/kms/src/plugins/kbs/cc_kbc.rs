// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::env;

use async_trait::async_trait;
use kbs_protocol::{
    client::KbsClient as KbsProtocolClient,
    token_provider::{AATokenProvider, TokenProvider},
    KbsClientCapabilities, ResourceUri,
};
use log::{info, warn};

use crate::{Error, Result};

use super::Kbc;

pub struct CcKbc {
    client: KbsProtocolClient<Box<dyn TokenProvider>>,
}

impl CcKbc {
    pub async fn new(kbs_host_url: &str) -> Result<Self> {
        let token_provider = AATokenProvider::new().await.map_err(|e| {
            Error::KbsClientError(format!("create AA token provider failed: {e:?}"))
        })?;
        let client = kbs_protocol::KbsClientBuilder::with_token_provider(
            Box::new(token_provider),
            kbs_host_url,
        );

        let client = match env::var("KBS_CERT") {
            Ok(cert_pem) => {
                info!("Use KBS public key cert");
                client.add_kbs_cert(&cert_pem)
            }
            Err(e) => {
                warn!("KBS_CERT get failed: {e:?}. Use no KBS public key certs.");
                client
            }
        };

        let client = client
            .build()
            .map_err(|e| Error::KbsClientError(format!("create kbs client failed: {e:?}")))?;

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
            .map_err(|e| Error::KbsClientError(format!("get resource failed: {e:?}")))?;
        Ok(secret)
    }
}
