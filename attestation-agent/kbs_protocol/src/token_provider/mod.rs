// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod test;
pub use test::*;

#[cfg(feature = "aa_ttrpc")]
pub mod aa;
#[cfg(feature = "aa_ttrpc")]
pub use aa::*;

use anyhow::*;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::keypair::TeeKeyPair;

#[async_trait]
pub trait TokenProvider: Send + Sync {
    /// Get token provisioned by Kbs and the tee pub key
    ///
    /// The returned value is a (Token, Private key) pair.
    async fn get_token(&self) -> crate::Result<(Token, TeeKeyPair)>;
}

/// The subset of registered JWT claims (RFC 7519) this crate reads locally
/// (no signature verification is performed here).
#[derive(Deserialize)]
struct Claims {
    exp: Option<f64>,
    nbf: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct Token {
    pub content: String,
    exp: Option<Duration>,
    nbf: Option<Duration>,
}

impl Token {
    pub fn new(token: String) -> Result<Self> {
        let claims_b64 = token
            .split('.')
            .nth(1)
            .ok_or_else(|| anyhow!("illegal token format"))?;
        let claims = URL_SAFE_NO_PAD.decode(claims_b64)?;
        let claims = serde_json::from_slice::<Claims>(&claims)?;
        Ok(Self {
            content: token,
            exp: claims.exp.map(Duration::from_secs_f64),
            nbf: claims.nbf.map(Duration::from_secs_f64),
        })
    }

    pub fn check_valid(&self) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        if let Some(exp) = self.exp
            && exp < now
        {
            bail!("token expired");
        }

        if let Some(nbf) = self.nbf
            && nbf > now
        {
            bail!("before validity");
        }

        Ok(())
    }
}
