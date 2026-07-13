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
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jwt_simple::{
    claims::JWTClaims,
    prelude::{Clock, UnixTimeStamp},
};
use serde_json::Value;

use crate::keypair::TeeKeyPair;

#[async_trait]
pub trait TokenProvider: Send + Sync {
    /// Get token provisioned by Kbs and the tee pub key
    ///
    /// The returned value is a (Token, Private key) pair.
    async fn get_token(&self) -> crate::Result<(Token, TeeKeyPair)>;
}

#[derive(Clone, Debug)]
pub struct Token {
    pub content: String,
    exp: Option<UnixTimeStamp>,
    nbf: Option<UnixTimeStamp>,
}

impl Token {
    pub fn new(token: String) -> Result<Self> {
        let claims_b64 = token
            .split('.')
            .nth(1)
            .ok_or_else(|| anyhow!("illegal token format"))?;
        let claims = URL_SAFE_NO_PAD.decode(claims_b64)?;
        let claims = serde_json::from_slice::<JWTClaims<Value>>(&claims)?;
        Ok(Self {
            content: token,
            exp: claims.expires_at,
            nbf: claims.invalid_before,
        })
    }

    pub fn check_valid(&self) -> Result<()> {
        let now = Clock::now_since_epoch();
        if let Some(exp) = self.exp {
            if exp < now {
                bail!("token expired");
            }
        }

        if let Some(nbf) = self.nbf {
            if nbf > now {
                bail!("before validity");
            }
        }

        Ok(())
    }
}
