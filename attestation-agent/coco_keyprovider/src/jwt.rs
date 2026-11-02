//
// SPDX-License-Identifier: Apache-2.0
//

//! EdDSA JWT signing for authenticating against the KBS admin API.
//!
//! Signing is delegated to `josekit`, a JOSE library that runs on the project's
//! OpenSSL backend. The produced token is a compact JWS with an `EdDSA` header
//! and a flat claims object (`role`, `iat`, `nbf`, `exp`).

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use josekit::jws::alg::eddsa::EddsaJwsSigner;
use josekit::jws::{EdDSA, JwsHeader};
use josekit::jwt::{self, JwtPayload};
use serde_json::Value;

/// Lifetime of the KBS admin JWT in seconds (2 hours).
const TOKEN_TTL_SECS: u64 = 2 * 60 * 60;

/// Load a PKCS#8 Ed25519 private key from a PEM string into a JWT signer.
pub(crate) fn load_signer(pem: &str) -> Result<EddsaJwsSigner> {
    EdDSA
        .signer_from_pem(pem.as_bytes())
        .context("parse Ed25519 private key PEM")
}

/// Sign a JWT for the given `role` with the Ed25519 `signer`.
///
/// The claims carry the `role` that KBS admin authorization matches against its
/// ACL, plus `iat`/`nbf` at the current time and `exp` two hours ahead. The
/// `alg: EdDSA` header is injected by josekit from the signer.
pub(crate) fn sign_eddsa_jwt(signer: &EddsaJwsSigner, role: &str) -> Result<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock set before the UNIX epoch")?
        .as_secs();

    let mut header = JwsHeader::new();
    header.set_token_type("JWT");

    // Set the NumericDate claims as integer seconds (RFC 7519). josekit's
    // set_issued_at/set_expires_at helpers store them as floats, which would
    // change the wire format the KBS verifier expects, so set them directly as
    // integers via set_claim.
    let mut payload = JwtPayload::new();
    payload
        .set_claim("role", Some(Value::String(role.to_string())))
        .context("set role claim")?;
    payload
        .set_claim("iat", Some(Value::Number(now.into())))
        .context("set iat claim")?;
    payload
        .set_claim("nbf", Some(Value::Number(now.into())))
        .context("set nbf claim")?;
    payload
        .set_claim("exp", Some(Value::Number((now + TOKEN_TTL_SECS).into())))
        .context("set exp claim")?;

    jwt::encode_with_signer(&payload, &header, signer).context("sign admin JWT")
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jwt::decode_with_verifier;
    use rstest::rstest;

    const TEST_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEIEZnvq1Yvu6PSYex6TgegTsIiBPvEehD0tW/zauo1JY9\n\
        -----END PRIVATE KEY-----\n";

    const TEST_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
        MCowBQYDK2VwAyEA8YnX0Wk26k7ThcX5by9vxNOsWPnljjS3AR2B+WDydwc=\n\
        -----END PUBLIC KEY-----\n";

    /// Public key of a *different* Ed25519 keypair, for the negative test.
    const OTHER_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
        MCowBQYDK2VwAyEA6u78cjK/NO+3WOCKDpBes11+KYcmSL7cpIfYMjtghSY=\n\
        -----END PUBLIC KEY-----\n";

    #[rstest]
    #[case::valid_pkcs8_pem(TEST_PRIVATE_PEM, true)]
    #[case::garbage("not a pem", false)]
    fn load_signer_validates_pem(#[case] pem: &str, #[case] loads: bool) {
        assert_eq!(
            load_signer(pem).is_ok(),
            loads,
            "unexpected result for PEM {pem:?}"
        );
    }

    /// A signed admin JWT must be a compact JWS (three segments) whose
    /// signature verifies under the signing key's public half, with an
    /// `alg: EdDSA` / `typ: JWT` header, and it must carry exactly the four
    /// expected claims: a flat string `role`, integer `iat`/`nbf` at signing
    /// time, and `exp` two hours later. No more, no fewer.
    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = load_signer(TEST_PRIVATE_PEM).unwrap();
        let token = sign_eddsa_jwt(&signer, "administrator").expect("signing must succeed");

        assert_eq!(
            token.split('.').count(),
            3,
            "compact JWS has three segments"
        );

        let verifier = EdDSA.verifier_from_pem(TEST_PUBLIC_PEM.as_bytes()).unwrap();
        let (payload, header) = decode_with_verifier(&token, &verifier).expect("token must verify");

        assert_eq!(header.algorithm(), Some("EdDSA"));
        assert_eq!(header.token_type(), Some("JWT"));

        let mut claims: Vec<&str> = payload.claims_set().keys().map(String::as_str).collect();
        claims.sort_unstable();
        assert_eq!(claims, vec!["exp", "iat", "nbf", "role"]);

        // `role` must be a flat string.
        assert_eq!(
            payload.claim("role").and_then(Value::as_str),
            Some("administrator")
        );

        // Timestamp claims must be integer seconds, `exp` two hours ahead.
        let iat = payload
            .claim("iat")
            .and_then(Value::as_u64)
            .expect("iat is an integer");
        let nbf = payload
            .claim("nbf")
            .and_then(Value::as_u64)
            .expect("nbf is an integer");
        let exp = payload
            .claim("exp")
            .and_then(Value::as_u64)
            .expect("exp is an integer");
        assert_eq!(nbf, iat);
        assert_eq!(exp - iat, TOKEN_TTL_SECS);
    }

    #[test]
    fn token_fails_verification_with_wrong_key() {
        let signer = load_signer(TEST_PRIVATE_PEM).unwrap();
        let token = sign_eddsa_jwt(&signer, "administrator").unwrap();

        let verifier = EdDSA
            .verifier_from_pem(OTHER_PUBLIC_PEM.as_bytes())
            .unwrap();
        assert!(
            decode_with_verifier(&token, &verifier).is_err(),
            "a token must not verify under a different key"
        );
    }
}
