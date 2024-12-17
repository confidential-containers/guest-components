// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a token provider which connects the attestation-agent

use async_trait::async_trait;
use serde::Deserialize;
use ttrpc::context;

use crate::{
    ttrpc_protos::{
        attestation_agent::GetTokenRequest, attestation_agent_ttrpc::AttestationAgentServiceClient,
    },
    Error, Result, TeeKeyPair, Token,
};

use super::TokenProvider;

const AA_SOCKET_FILE: &str =
    "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

const TOKEN_TYPE: &str = "kbs";

pub struct AATokenProvider {
    client: AttestationAgentServiceClient,
}

#[derive(Deserialize)]
struct Message {
    token: String,
    tee_keypair: String,
}

impl AATokenProvider {
    pub async fn new() -> Result<Self> {
        let c = ttrpc::r#async::Client::connect(AA_SOCKET_FILE)
            .map_err(|e| Error::AATokenProvider(format!("ttrpc connect failed {e:?}")))?;
        let client = AttestationAgentServiceClient::new(c);
        Ok(Self { client })
    }
}

#[async_trait]
impl TokenProvider for AATokenProvider {
    async fn get_token(&self) -> Result<(Token, TeeKeyPair)> {
        let req = GetTokenRequest {
            TokenType: TOKEN_TYPE.to_string(),
            ..Default::default()
        };
        let bytes = self
            .client
            .get_token(context::with_timeout(50 * 1000 * 1000 * 1000), &req)
            .await
            .map_err(|e| Error::AATokenProvider(format!("cal ttrpc failed: {e:?}")))?;
        let message: Message = serde_json::from_slice(&bytes.Token).map_err(|e| {
            Error::AATokenProvider(format!("deserialize attestation-agent reply failed: {e:?}"))
        })?;
        let token = Token::new(message.token)
            .map_err(|e| Error::AATokenProvider(format!("deserialize token failed: {e:?}")))?;
        let tee_keypair = TeeKeyPair::from_pem(&message.tee_keypair).map_err(|e| {
            Error::AATokenProvider(format!("deserialize tee keypair failed: {e:?}"))
        })?;
        Ok((token, tee_keypair))
    }
}
