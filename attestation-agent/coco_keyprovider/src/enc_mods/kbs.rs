// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use jwt_simple::prelude::{Claims, Duration, Ed25519KeyPair, EdDSAKeyPairLike};
use log::debug;
use reqwest::Url;

const KBS_URL_PATH_PREFIX: &str = "kbs/v0/resource";

/// Register the given key with kid into the kbs. This request will be authorized with a
/// JWT token, which will be signed by the private_key.
pub(crate) async fn register_kek(
    private_key: &Ed25519KeyPair,
    kbs_addr: &Url,
    key: Vec<u8>,
    kid: &str,
) -> Result<()> {
    let kid = kid.strip_prefix('/').unwrap_or(kid);
    let claims = Claims::create(Duration::from_hours(2));
    let token = private_key.sign(claims)?;
    debug!("sign claims.");

    let client = reqwest::Client::new();
    let mut resource_url = kbs_addr.clone();

    let path = format!("{KBS_URL_PATH_PREFIX}/{kid}");

    resource_url.set_path(&path);

    debug!("register KEK into {resource_url}");
    let _ = client
        .post(resource_url)
        .header("Content-Type", "application/octet-stream")
        .bearer_auth(token)
        .body(key)
        .send()
        .await?;

    Ok(())
}
