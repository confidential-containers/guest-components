// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod error;
pub mod layout;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64, Engine};
use const_format::concatcp;
use jose_jwa::Signing;
use jose_jwk::{EcCurves, Jwk};
use jose_jws::{Flattened, Protected, Unprotected};
use p256::ecdsa::{signature::Signer, SigningKey};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs;

use self::layout::{envelope::EnvelopeSecret, vault::VaultSecret};

use kms::{Annotations, ProviderSettings};

use crate::hub::CDH_BASE_DIR;

pub use error::{Result, SecretError};

/// Path to the directory containing sealed-secret signing credentials.
pub const SIGNING_CREDENTIALS_PATH: &str = concatcp!(CDH_BASE_DIR, "/sealed-secret");

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SecretContent {
    Envelope(EnvelopeSecret),
    Vault(VaultSecret),
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Secret {
    pub version: String,

    #[serde(flatten)]
    pub r#type: SecretContent,
}

pub const VERSION: &str = "0.1.0";

pub async fn unseal_secret(secret: &[u8]) -> Result<Vec<u8>> {
    let secret_string = String::from_utf8(secret.to_vec())
        .map_err(|_| SecretError::ParseFailed("Secret string must be UTF-8"))?;

    let skip_verification =
        std::env::var("SKIP_SEALED_SECRET_VERIFICATION").unwrap_or("".to_string()) == "true";

    let secret = Secret::from_signed_base64_string(secret_string, skip_verification).await?;
    secret.unseal().await
}

impl Secret {
    pub async fn unseal(&self) -> Result<Vec<u8>> {
        if self.version != VERSION {
            return Err(SecretError::VersionError);
        }

        match &self.r#type {
            SecretContent::Envelope(env) => env.unseal().await.map_err(Into::into),
            SecretContent::Vault(v) => v.unseal().await.map_err(Into::into),
        }
    }

    pub async fn from_signed_base64_string(
        secret: String,
        skip_verification: bool,
    ) -> Result<Self> {
        let payload = match skip_verification {
            false => {
                let secret = secret.trim_start_matches("sealed.").to_string();

                let jws: Flattened = secret
                    .clone()
                    .parse()
                    .map_err(|_| SecretError::ParseFailed("Failed to parse JWS"))?;

                let kid = jws
                    .signature
                    .protected
                    .as_ref()
                    .and_then(|p| p.oth.kid.as_ref())
                    .ok_or(SecretError::ParseFailed("Could not find kid"))?;

                let alg = jws
                    .signature
                    .protected
                    .as_ref()
                    .and_then(|p| p.oth.alg)
                    .ok_or(SecretError::ParseFailed("Could not get algorithm"))?;

                let sig = jws.signature.signature.to_vec();

                let verification_key = Secret::get_kid(kid).await?;

                // Try validating the secret with the key using whatever
                // algorithm is specified in the JWS header.
                match alg {
                    Signing::Es256 => Secret::validate_es256(secret, verification_key, sig)?,
                    _ => return Err(SecretError::BadSigningKey("JWS algorithm must be ES256")),
                }

                jws.payload
                    .ok_or(SecretError::ParseFailed("Could not find JWS Payload"))?
                    .to_vec()
            }
            true => {
                // The fake headers we have been using are not compatible with the
                // JWS crate. If verification is disabled, parse the secret manually.
                let sections: Vec<_> = secret.split('.').collect();

                if sections.len() != 4 {
                    return Err(SecretError::ParseFailed("malformed input sealed secret"));
                }

                let payload = b64.decode(sections[2]).map_err(|_| {
                    SecretError::ParseFailed(
                        "failed to decode secret body as base64 (URL-safe without padding)",
                    )
                })?;

                payload.to_vec()
            }
        };

        let secret: Secret = serde_json::from_slice(&payload).map_err(|_| {
            SecretError::ParseFailed(
                "malformed input sealed secret format (json deserialization failed)",
            )
        })?;

        Ok(secret)
    }

    /// Given a key id, get the key.
    /// If the key id is in the form of a resource URI, use the KMS.
    /// Otherwise, look for a local credential (provisioned to the fs
    /// at CDH startup).
    async fn get_kid(kid: &String) -> Result<Vec<u8>> {
        if kid.starts_with("kbs://") {
            let verification_key = kms::new_getter("kbs", ProviderSettings::default())
                .await?
                .get_secret(kid, &Annotations::default())
                .await?;

            return Ok(verification_key);
        }

        // Get key as local credential.
        let base = fs::canonicalize(SIGNING_CREDENTIALS_PATH).map_err(|_| {
            SecretError::ParseFailed("KID is invalid. Must be a KBS URI or a credential path.")
        })?;
        let kid_path = base.join(kid);

        // check for directory traversal
        let kid_path = fs::canonicalize(kid_path)?;
        if !kid_path.starts_with(&base) {
            return Err(SecretError::ParseFailed("Invalid KID Key Path"));
        }

        let verification_key = tokio::fs::read(kid_path).await?;

        Ok(verification_key)
    }

    fn validate_es256(secret: String, verification_key: Vec<u8>, signature: Vec<u8>) -> Result<()> {
        let jwk: Jwk = serde_json::from_slice(&verification_key)?;

        let public_key: p256::PublicKey = match &jwk.key {
            jose_jwk::Key::Ec(ec) if ec.crv == EcCurves::P256 => ec
                .try_into()
                .map_err(|_| SecretError::BadSigningKey("Could not parse verification key."))?,
            _ => return Err(SecretError::BadSigningKey("Key must be P256")),
        };

        let verifying_key = VerifyingKey::from(&public_key);

        let sections: Vec<&str> = secret.split('.').collect();
        let signing_input = format!("{}.{}", sections[0], sections[1]);

        let sig = Signature::from_slice(&signature)?;
        verifying_key.verify(signing_input.as_bytes(), &sig)?;

        Ok(())
    }

    pub fn to_signed_base64_string(&self, signing_key: Jwk, signing_kid: String) -> Result<String> {
        let secret_json = serde_json::to_string(&self)
            .map_err(|_| SecretError::ParseFailed("JSON serialization failed"))?;

        let signing_key: p256::SecretKey = match &signing_key.key {
            jose_jwk::Key::Ec(ec) if ec.crv == EcCurves::P256 => ec
                .try_into()
                .map_err(|_| SecretError::BadSigningKey("Could not parse verification key."))?,
            _ => {
                return Err(SecretError::BadSigningKey(
                    "Key must be EC P256 private key",
                ))
            }
        };

        let signing_key = SigningKey::from(&signing_key);

        let header = Protected {
            oth: Unprotected {
                alg: Some(Signing::Es256),
                kid: Some(signing_kid),
                ..Default::default()
            },
            ..Default::default()
        };

        let header_json = serde_json::to_vec(&header)?;
        let header_b64 = b64.encode(&header_json);
        let payload_b64 = b64.encode(secret_json.as_bytes());

        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature: Signature = signing_key.sign(signing_input.as_bytes());

        let signature_b64 = b64.encode(signature.to_bytes());

        Ok(format!("sealed.{header_b64}.{payload_b64}.{signature_b64}",))
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use crypto::WrapType;
    use jose_jwk::Jwk;
    use rstest::rstest;

    use crate::secret::layout::{
        envelope::EnvelopeSecret,
        vault::{Annotations, ProviderSettings, VaultSecret},
    };

    use super::{Secret, SecretContent, SIGNING_CREDENTIALS_PATH};

    #[rstest]
    #[case(include_str!("./tests/envelope-1.json"), Secret {
        version: "0.1.0".into(),
        r#type: SecretContent::Envelope(EnvelopeSecret {
            provider: "aliyun".into(),
            provider_settings: ProviderSettings::default(),
            key_id: "xxx".into(),
            encrypted_key: "yyy".into(),
            encrypted_data: "zzz".into(),
            wrap_type: WrapType::Aes256Gcm,
            iv: "www".into(),
            annotations: Annotations::default(),
        }),
    })]
    #[case(include_str!("./tests/vault-1.json"), Secret {
        version: "0.1.0".into(),
        r#type: SecretContent::Vault(VaultSecret {
            provider: "aliyun".into(),
            provider_settings: ProviderSettings::default(),
            annotations: Annotations::default(),
            name: "xxx".into(),
        }),
    })]
    #[case(include_str!("./tests/vault-2.json"), Secret {
        version: "0.1.0".into(),
        r#type: SecretContent::Vault(VaultSecret {
            provider: "kbs".into(),
            provider_settings: ProviderSettings::default(),
            annotations: Annotations::default(),
            name: "kbs:///one/2/trois".into(),
        }),
    })]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn serialize_deserialize(#[case] secret_json: &str, #[case] secret_object: Secret) {
        let serialized = serde_json::to_string_pretty(&secret_object).expect("serialize failed");
        assert_json_eq!(secret_json, serialized);

        let parsed: Secret = serde_json::from_str(secret_json).expect("deserialize failed");
        assert_eq!(parsed, secret_object);

        let jwk = include_str!("./tests/test-key.json");
        let jwk: Jwk = serde_json::from_str(&jwk).expect("Could not parse signing JWK");

        let kid = "test-key".to_string();
        let kid_cred_path = format!("{SIGNING_CREDENTIALS_PATH}/{}", &kid);

        std::fs::create_dir_all(SIGNING_CREDENTIALS_PATH).unwrap();
        std::fs::write(kid_cred_path, serde_json::to_string(&jwk).unwrap()).unwrap();

        let secret_string = secret_object
            .to_signed_base64_string(jwk, kid)
            .expect("serialization failed");

        let secret_from_string = Secret::from_signed_base64_string(secret_string, false)
            .await
            .expect("deserialization failed");

        assert_eq!(secret_from_string, secret_object);
    }

    // Negative test to check what happens when a secret is tampered with.
    // Different cases tamper with the secret at different offsets.
    #[rstest]
    #[case(50)] // Header
    #[case(200)] // Payload
    #[case(250)] // Signature
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn check_tampering(#[case] offset: usize) {
        let secret_object = Secret {
            version: "0.1.0".into(),
            r#type: SecretContent::Vault(VaultSecret {
                provider: "kbs".into(),
                provider_settings: ProviderSettings::default(),
                annotations: Annotations::default(),
                name: "kbs:///one/2/trois".into(),
            }),
        };

        let jwk = include_str!("./tests/test-key.json");
        let jwk: Jwk = serde_json::from_str(&jwk).expect("Could not parse signing JWK");

        let kid = "test-key".to_string();
        let kid_cred_path = format!("{SIGNING_CREDENTIALS_PATH}/{}", &kid);

        std::fs::create_dir_all(SIGNING_CREDENTIALS_PATH).unwrap();
        std::fs::write(kid_cred_path, serde_json::to_string(&jwk).unwrap()).unwrap();

        let secret_string = secret_object
            .to_signed_base64_string(jwk, kid)
            .expect("serialization failed");

        // Modify the payload
        let mut chars: Vec<char> = secret_string.chars().collect();
        if let Some(ch) = chars.get_mut(offset) {
            *ch = if *ch == 'X' { 'Y' } else { 'X' };
        }
        let secret_string = chars.into_iter().collect();

        assert!(Secret::from_signed_base64_string(secret_string, false)
            .await
            .is_err());
    }

    // Negative test to check a signature with the wrong key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn check_wrong_key() {
        let secret_object = Secret {
            version: "0.1.0".into(),
            r#type: SecretContent::Vault(VaultSecret {
                provider: "kbs".into(),
                provider_settings: ProviderSettings::default(),
                annotations: Annotations::default(),
                name: "kbs:///one/2/trois".into(),
            }),
        };

        let jwk = include_str!("./tests/test-key.json");
        let jwk: Jwk = serde_json::from_str(&jwk).expect("Could not parse signing JWK");

        let jwk2 = include_str!("./tests/test-key-2.json");
        let jwk2: Jwk = serde_json::from_str(&jwk2).expect("Could not parse signing JWK");

        let kid = "test-key".to_string();
        let kid_cred_path = format!("{SIGNING_CREDENTIALS_PATH}/{}", &kid);

        std::fs::create_dir_all(SIGNING_CREDENTIALS_PATH).unwrap();
        std::fs::write(kid_cred_path, serde_json::to_string(&jwk).unwrap()).unwrap();

        let secret_string = secret_object
            .to_signed_base64_string(jwk2, kid)
            .expect("serialization failed");

        assert!(Secret::from_signed_base64_string(secret_string, false)
            .await
            .is_err());
    }

    #[rstest]
    fn test_no_padding(#[values(0, 1, 2, 3)] name_size: usize) {
        let name = "0".repeat(name_size);

        let secret = Secret {
            version: "0.1.0".into(),
            r#type: SecretContent::Vault(VaultSecret {
                provider: "kbs".into(),
                provider_settings: ProviderSettings::default(),
                annotations: Annotations::default(),
                name,
            }),
        };

        let serialized = serde_json::to_string_pretty(&secret).unwrap();

        assert!(!serialized.contains("="));
    }
}
