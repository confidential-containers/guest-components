// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod layout;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as b64, Engine};
use serde::{Deserialize, Serialize};

use self::layout::{envelope::EnvelopeSecret, vault::VaultSecret};

use crate::{Result, SecretError};

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

    // TODO: check the signature
    pub fn from_signed_base64_string(secret: String) -> Result<Self> {
        let sections: Vec<_> = secret.split('.').collect();

        if sections.len() != 4 {
            return Err(SecretError::ParseFailed("malformed input sealed secret"));
        }

        let secret_json = b64
            .decode(sections[2])
            .map_err(|_| SecretError::ParseFailed("base64 decode Secret body"))?;

        let secret: Secret = serde_json::from_slice(&secret_json).map_err(|_| {
            SecretError::ParseFailed(
                "malformed input sealed secret format (json deserialization failed)",
            )
        })?;

        Ok(secret)
    }

    // TODO: add real signature generation
    pub fn to_signed_base64_string(&self) -> Result<String> {
        let secret_json = serde_json::to_string(&self)
            .map_err(|_| SecretError::ParseFailed("JSON serialization failed"))?;

        let secret_base64 = b64.encode(secret_json);

        let secret_string = format!("sealed.fakejwsheader.{}.fakesignature", secret_base64);

        Ok(secret_string)
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use crypto::WrapType;
    use rstest::rstest;

    use crate::{
        secret::layout::{envelope::EnvelopeSecret, vault::VaultSecret},
        Annotations, ProviderSettings,
    };

    use super::{Secret, SecretContent};

    #[rstest]
    #[case(include_str!("../../tests/envelope-1.json"), Secret {
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
    #[case(include_str!("../../tests/vault-1.json"), Secret {
        version: "0.1.0".into(),
        r#type: SecretContent::Vault(VaultSecret {
            provider: "aliyun".into(),
            provider_settings: ProviderSettings::default(),
            annotations: Annotations::default(),
            name: "xxx".into(),
        }),
    })]
    #[case(include_str!("../../tests/vault-2.json"), Secret {
        version: "0.1.0".into(),
        r#type: SecretContent::Vault(VaultSecret {
            provider: "kbs".into(),
            provider_settings: ProviderSettings::default(),
            annotations: Annotations::default(),
            name: "kbs:///one/2/trois".into(),
        }),
    })]
    fn serialize_deserialize(#[case] secret_json: &str, #[case] secret_object: Secret) {
        let serialized = serde_json::to_string_pretty(&secret_object).expect("serialize failed");
        assert_json_eq!(secret_json, serialized);

        let parsed: Secret = serde_json::from_str(secret_json).expect("deserialize failed");
        assert_eq!(parsed, secret_object);

        let secret_string = secret_object
            .to_signed_base64_string()
            .expect("serialization failed");

        let secret_from_string =
            Secret::from_signed_base64_string(secret_string).expect("deserialiation failed");

        assert_eq!(secret_from_string, secret_object);
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
