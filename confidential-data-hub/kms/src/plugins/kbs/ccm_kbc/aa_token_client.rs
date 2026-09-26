// Copyright (c) Fortanix, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

//! Asks the attestation agent for a 'ccm_as' token: the CCM-issued workload
//! certificate and the private key it certifies.

use anyhow::{Context, Result};
use protos::ttrpc::aa::{
    attestation_agent::GetTokenRequest, attestation_agent_ttrpc::AttestationAgentServiceClient,
};
use serde::Deserialize;
use ttrpc::context;

const TOKEN_TYPE: &str = "ccm_as";

const TIMEOUT_NANOS: i64 = 50 * 1000 * 1000 * 1000;

#[derive(Deserialize)]
pub(super) struct CcmAsCredential {
    pub cert_pem: String,
    pub key_pem: String,
}

pub(super) async fn get_ccm_as_credential(aa_socket: &str) -> Result<CcmAsCredential> {
    let conn = ttrpc::r#async::Client::connect(aa_socket)
        .await
        .context("ttrpc connect to attestation-agent failed")?;
    let client = AttestationAgentServiceClient::new(conn);

    let req = GetTokenRequest {
        TokenType: TOKEN_TYPE.to_string(),
        ..Default::default()
    };

    let resp = client
        .get_token(context::with_timeout(TIMEOUT_NANOS), &req)
        .await
        .context("attestation-agent GetToken(ccm_as) failed")?;

    serde_json::from_slice(&resp.Token).context("deserialize ccm_as token payload failed")
}
