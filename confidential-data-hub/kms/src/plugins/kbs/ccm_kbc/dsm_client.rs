// Copyright (c) Fortanix, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

// DSM client: authenticate with the CCM-issued workload certificate,
// then unwrap a key.

use anyhow::{Context, Result, bail};
use base64::Engine;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(super) async fn unwrap_key(
    endpoint: &str,
    cert_pem: &str,
    key_pem: &str,
    app_uuid: &str,
    key_uuid: Uuid,
) -> Result<Vec<u8>> {
    // Cert chain + private key in one PEM blob become the reqwest TLS client
    // identity. DSM authenticates the mTLS handshake.
    let mut identity_pem = String::with_capacity(cert_pem.len() + key_pem.len() + 1);
    identity_pem.push_str(cert_pem.trim_end());
    identity_pem.push('\n');
    identity_pem.push_str(key_pem);

    let identity = reqwest::Identity::from_pem(identity_pem.as_bytes())
        .context("build TLS identity from cert and key failed")?;

    let http = Client::builder()
        .use_rustls_tls()
        .identity(identity)
        .build()
        .context("build mTLS client failed")?;

    let token = authenticate(&http, endpoint, app_uuid).await?;
    export_sobject(&http, endpoint, &token, key_uuid).await
}

async fn authenticate(http: &Client, endpoint: &str, app_uuid: &str) -> Result<String> {
    let url = format!("{endpoint}/sys/v1/session/auth");
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{app_uuid}:"));

    let resp = http
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Basic {basic}"))
        .send()
        .await
        .context("DSM auth POST failed")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("DSM auth returned {status}: {body}");
    }

    #[derive(Deserialize)]
    struct AuthResp {
        access_token: String,
    }

    let auth: AuthResp = resp
        .json()
        .await
        .context("DSM auth response was not valid JSON")?;
    Ok(auth.access_token)
}

async fn export_sobject(
    http: &Client,
    endpoint: &str,
    token: &str,
    kek_uuid: Uuid,
) -> Result<Vec<u8>> {
    let url = format!("{endpoint}/crypto/v1/keys/export");

    #[derive(Serialize)]
    struct ExportReq {
        kid: String,
    }

    #[derive(Deserialize)]
    struct ExportResp {
        value: String,
    }

    let resp = http
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .json(&ExportReq {
            kid: kek_uuid.to_string(),
        })
        .send()
        .await
        .context("DSM export POST failed")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("DSM export returned {status}: {body}");
    }

    let body: ExportResp = resp
        .json()
        .await
        .context("DSM export response was not valid JSON")?;

    base64::engine::general_purpose::STANDARD
        .decode(body.value.as_bytes())
        .context("DSM export 'value' was not valid base64")
}
