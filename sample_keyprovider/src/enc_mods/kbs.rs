// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{net::SocketAddr, str::FromStr};

use anyhow::*;
use jwt_simple::prelude::{Ed25519KeyPair, Claims, Duration, EdDSAKeyPairLike};
use log::debug;
use reqwest::Url;

/// Register the given key with kid into the kbs. This request will be authorized with a
/// JWT token, which will be signed by the private_key.
pub(crate) async fn register_kek(private_key: &Ed25519KeyPair, kbs_addr: &SocketAddr, key: Vec<u8>, kid: &str) -> Result<()> {
    let claims = Claims::create(Duration::from_hours(2));
    let token = private_key.sign(claims)?;

    let client = reqwest::Client::new();
    let mut resource_url = Url::from_str(&kbs_addr.to_string()).context("kbs_addr to url")?;
    resource_url.set_path(kid);

    debug!("register KEK into {}", resource_url);
    let _ = client.post(resource_url)
        .bearer_auth(token)
        .body(key)
        .send()
        .await?;

    Ok(())
}
