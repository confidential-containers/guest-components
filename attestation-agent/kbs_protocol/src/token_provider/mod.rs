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
use std::time::{SystemTime, UNIX_EPOCH};

use crate::keypair::TeeKeyPair;

#[async_trait]
pub trait TokenProvider: Send + Sync {
    /// Get token provisioned by Kbs and the tee pub key
    ///
    /// The returned value is a (Token, Private key) pair.
    async fn get_token(&self) -> crate::Result<(Token, TeeKeyPair)>;
}

/// The subset of the RFC 7519 JWT claims needed to check the validity of
/// a KBS-provisioned token. `NumericDate` claim values (`exp`, `nbf`) are
/// integer seconds since the UNIX epoch.
#[derive(Deserialize)]
struct TokenClaims {
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    nbf: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Token {
    pub content: String,
    exp: Option<u64>,
    nbf: Option<u64>,
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock set before the UNIX epoch")?
        .as_secs())
}

impl Token {
    pub fn new(token: String) -> Result<Self> {
        let claims_b64 = token
            .split('.')
            .nth(1)
            .ok_or_else(|| anyhow!("illegal token format"))?;
        let claims = URL_SAFE_NO_PAD.decode(claims_b64)?;
        let claims = serde_json::from_slice::<TokenClaims>(&claims)?;
        Ok(Self {
            content: token,
            exp: claims.exp,
            nbf: claims.nbf,
        })
    }

    pub fn check_valid(&self) -> Result<()> {
        let now = unix_now()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Base64url of `{"alg":"EdDSA","typ":"JWT"}` — a syntactically valid
    /// JWS header; the payload is all `Token::new` looks at.
    const HEADER: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9";
    const SIGNATURE: &str = "signature";

    /// A timestamp far in the past / future relative to any test run.
    const PAST: u64 = 1;
    const FUTURE: u64 = 4_102_444_800; // 2100-01-01T00:00:00Z

    fn make_token(claims: &str) -> String {
        format!("{HEADER}.{}.{SIGNATURE}", URL_SAFE_NO_PAD.encode(claims))
    }

    fn token_with_claims(claims: &str) -> Token {
        Token::new(make_token(claims)).expect("token must parse")
    }

    #[test]
    fn parse_valid_token() {
        let token = token_with_claims(&format!(
            "{{\"iat\":{PAST},\"exp\":{FUTURE},\"nbf\":{PAST}}}"
        ));
        token.check_valid().expect("token must be valid");
    }

    #[test]
    fn parse_hardcoded_kbs_token() {
        // A real KBS-issued token (same as `TestTokenProvider` uses); guards
        // the claims wire format against regressions. Only parsing is
        // asserted to keep the test timeless.
        let token = Token::new(super::test::HARDCODED.to_string()).expect("token must parse");
        assert_eq!(token.exp, Some(2_006_149_618));
        assert_eq!(token.nbf, Some(1_690_789_618));
    }

    #[test]
    fn expired_token_is_invalid() {
        let token = token_with_claims(&format!("{{\"iat\":{PAST},\"exp\":{PAST},\"nbf\":{PAST}}}"));
        assert!(token.check_valid().is_err());
    }

    #[test]
    fn token_before_validity_is_invalid() {
        let token = token_with_claims(&format!(
            "{{\"iat\":{PAST},\"exp\":{FUTURE},\"nbf\":{FUTURE}}}"
        ));
        assert!(token.check_valid().is_err());
    }

    #[test]
    fn missing_claims_default_to_none() {
        let token = token_with_claims("{}");
        assert!(token.exp.is_none());
        assert!(token.nbf.is_none());
        token.check_valid().expect("token without claims is valid");
    }

    #[test]
    fn malformed_claims_rejected() {
        let token = make_token("not json at all");
        assert!(Token::new(token).is_err());
    }

    #[test]
    fn malformed_base64_rejected() {
        let token = format!("{HEADER}.!!!.{SIGNATURE}");
        assert!(Token::new(token).is_err());
    }

    #[test]
    fn illegal_token_format_rejected() {
        assert!(Token::new("no-separator".to_string()).is_err());
    }
}
