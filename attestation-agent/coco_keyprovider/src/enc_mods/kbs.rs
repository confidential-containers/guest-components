// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Result, bail};
use openssl::pkey::{PKey, Private};
use reqwest::Url;
use tracing::debug;

use crate::jwt;

const KBS_URL_PATH_PREFIX: &str = "kbs/v0/resource";

/// Register the given key with kid into the kbs. This request will be authorized with a
/// JWT token signed by the private key. The JWT carries `role` in its claims, which the
/// KBS admin authorization checks against its ACL.
pub(crate) async fn register_kek(
    private_key: &PKey<Private>,
    kbs_addr: &Url,
    key: Vec<u8>,
    kid: &str,
    role: &str,
) -> Result<()> {
    let kid = kid.strip_prefix('/').unwrap_or(kid);
    let token = jwt::sign_eddsa_jwt(private_key, role)?;
    debug!("sign claims.");

    let client = reqwest::Client::new();
    let mut resource_url = kbs_addr.clone();

    let path = format!("{KBS_URL_PATH_PREFIX}/{kid}");

    resource_url.set_path(&path);

    debug!("register KEK into {resource_url}");
    let response = client
        .post(resource_url)
        .header("Content-Type", "application/octet-stream")
        .bearer_auth(token)
        .body(key)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        bail!("register KEK failed: HTTP {status}: {text}");
    }

    Ok(())
}
