// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{Annotations, Error, Getter, Result};
use async_trait::async_trait;
use kbs_protocol::KbsClientCapabilities;
use resource_uri::ResourceUri;

const TOKEN_TYPE: &str = "coco_as";

#[derive(Default)]
pub struct ResourceKbsClient;

#[async_trait]
impl Getter for ResourceKbsClient {
    async fn get_secret(&mut self, uri: &str, _annotations: &Annotations) -> Result<Vec<u8>> {
        // Generate TEE key pair

        let tee_key = kbs_protocol::TeeKeyPair::new()
            .map_err(|e| Error::ResourceKbsClientError(e.to_string()))?;
        let tee_key_pem_str = tee_key
            .to_pkcs1_pem()
            .map_err(|e| Error::ResourceKbsClientError(e.to_string()))?;
        let tee_pubkey = tee_key
            .export_pubkey()
            .map_err(|e| Error::ResourceKbsClientError(e.to_string()))?;
        let tee_pubkey_str = serde_json::to_string(&tee_pubkey)
            .map_err(|e| Error::ResourceKbsClientError(e.to_string()))?;

        // Call AA to get Attestation Token and check validation of the token

        let aa_client = crate::attestation::AAClient::new().await?;
        let token_bytes = aa_client.get_token(TOKEN_TYPE, &tee_pubkey_str).await?;
        let token_str = std::str::from_utf8(&token_bytes)
            .map_err(|e| Error::ResourceKbsClientError(e.to_string()))?;
        let token = kbs_protocol::Token::new(token_str.to_string())
            .map_err(|e| Error::ResourceKbsClientError(e.to_string()))?;
        token
            .check_valid()
            .map_err(|e| Error::ResourceKbsClientError(e.to_string()))?;

        // Use KBS protocol to request KBS to get resource with Attestation Token

        let resource_uri = ResourceUri::try_from(uri).map_err(|_| {
            Error::ResourceKbsClientError(format!("illegal kbs resource uri: {uri}"))
        })?;

        let dummy_token_provider = kbs_protocol::token_provider::AATokenProvider::new()
            .await
            .map_err(|e| {
                Error::ResourceKbsClientError(format!("create dummy AA token provider failed: {e}"))
            })?;
        let kbs_client = kbs_protocol::KbsClientBuilder::with_token_provider(
            Box::new(dummy_token_provider),
            &resource_uri.kbs_addr,
        )
        .set_token(token_str)
        .set_tee_key(tee_key_pem_str.as_ref())
        .build()
        .map_err(|e| Error::ResourceKbsClientError(format!("create kbs client failed: {e}")))?;

        let secret = kbs_client
            .get_resource(resource_uri)
            .await
            .map_err(|e| Error::ResourceKbsClientError(format!("get resource failed: {e}")))?;

        Ok(secret)
    }
}
