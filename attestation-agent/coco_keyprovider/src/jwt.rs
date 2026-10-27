// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Minimal EdDSA JWT support for authenticating against the KBS admin API.
//!
//! This replaces the `jwt-simple` crate: it produces the same wire format
//! (a compact JWS with an `EdDSA` header and a flat claims object) on top
//! of the project's OpenSSL backend.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use serde_json::json;

/// Lifetime of the KBS admin JWT in seconds (2 hours).
const TOKEN_TTL_SECS: u64 = 2 * 60 * 60;

/// Load a PKCS#8 Ed25519 private key from a PEM string.
pub(crate) fn load_private_key(pem: &str) -> Result<PKey<Private>> {
    PKey::private_key_from_pem(pem.as_bytes()).context("parse Ed25519 private key PEM")
}

/// Sign a JWT for the given `role` with the Ed25519 `key`.
///
/// The claims replicate what `jwt-simple`'s
/// `Claims::with_custom_claims(.., Duration::from_hours(2))` used to produce:
/// the custom `role` claim flattened into the top-level object, `iat`/`nbf`
/// set to the current time and `exp` two hours ahead. The KBS admin
/// authorization matches the `role` claim against its ACL.
pub(crate) fn sign_eddsa_jwt(key: &PKey<Private>, role: &str) -> Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock set before the UNIX epoch")?
        .as_secs();

    let header = json!({
        "alg": "EdDSA",
        "typ": "JWT",
    });
    let claims = json!({
        "role": role,
        "iat": now,
        "nbf": now,
        "exp": now + TOKEN_TTL_SECS,
    });

    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string()),
    );

    // PureEdDSA (Ed25519) supports neither a prehash nor streaming: the
    // `MessageDigest` pattern used for ECDSA/RSA keys is rejected by
    // `EVP_DigestSignInit`, and `update` + `sign_to_vec` is unsupported.
    // `sign_oneshot_to_vec` is the only supported signing path.
    let mut signer = Signer::new_without_digest(key)?;
    let signature = signer.sign_oneshot_to_vec(signing_input.as_bytes())?;

    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use openssl::pkey::Id;
    use openssl::sign::Verifier;
    use serde_json::Value;

    #[test]
    fn load_private_key_from_pkcs8_pem() {
        let key = PKey::generate_ed25519().unwrap();
        let pem = String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        load_private_key(&pem).expect("PKCS#8 Ed25519 PEM must load");
    }

    #[test]
    fn load_private_key_rejects_garbage() {
        assert!(load_private_key("not a pem").is_err());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = PKey::generate_ed25519().unwrap();
        let token = sign_eddsa_jwt(&key, "administrator").expect("signing must succeed");

        let mut segments = token.split('.');
        let header_b64 = segments.next().expect("header segment");
        let claims_b64 = segments.next().expect("claims segment");
        let signature_b64 = segments.next().expect("signature segment");
        assert!(segments.next().is_none(), "exactly three segments expected");

        let header: Value = serde_json::from_slice(&B64.decode(header_b64).unwrap()).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "JWT");

        let claims: Value = serde_json::from_slice(&B64.decode(claims_b64).unwrap()).unwrap();
        assert_eq!(claims["role"], "administrator");
        let iat = claims["iat"].as_u64().expect("iat is an integer");
        let nbf = claims["nbf"].as_u64().expect("nbf is an integer");
        let exp = claims["exp"].as_u64().expect("exp is an integer");
        assert_eq!(nbf, iat);
        assert_eq!(exp - iat, TOKEN_TTL_SECS);

        // Verify the signature with the corresponding public key.
        let public_key =
            PKey::public_key_from_raw_bytes(&key.raw_public_key().unwrap(), Id::ED25519).unwrap();
        let signature = B64.decode(signature_b64).unwrap();
        let signing_input = format!("{header_b64}.{claims_b64}");
        let mut verifier = Verifier::new_without_digest(&public_key).unwrap();
        assert!(
            verifier
                .verify_oneshot(&signature, signing_input.as_bytes())
                .unwrap()
        );

        // A tampered payload must not verify.
        let mut verifier = Verifier::new_without_digest(&public_key).unwrap();
        assert!(
            !verifier
                .verify_oneshot(&signature, b"tampered.signing_input")
                .unwrap()
        );
    }
}
