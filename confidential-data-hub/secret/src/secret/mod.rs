// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod layout;

use serde::{Deserialize, Serialize};

use self::layout::{envelope::Envelope, vault::VaultSecret};

use crate::{Error, Result};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SecretContent {
    Envelope(Envelope),
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
            return Err(Error::UnsealEnvelopeFailed(format!(
                "Unsupported secret version {}. Only support {VERSION} now.",
                self.version
            )));
        }

        match &self.r#type {
            SecretContent::Envelope(env) => env.unseal().await,
            SecretContent::Vault(_) => todo!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use crypto::WrapType;
    use kms::{Annotations, ProviderSettings};
    use rstest::rstest;

    use crate::secret::layout::{envelope::Envelope, vault::VaultSecret};

    use super::{Secret, SecretContent};

    #[rstest]
    #[case(include_str!("../../test/envelope-1.json"), Secret {
        version: "0.1.0".into(),
        r#type: SecretContent::Envelope(Envelope {
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
    #[case(include_str!("../../test/vault-1.json"), Secret {
        version: "0.1.0".into(),
        r#type: SecretContent::Vault(VaultSecret {
            provider: "aliyun".into(),
            provider_settings: ProviderSettings::default(),
            annotations: Annotations::default(),
            name: "xxx".into(),
        }),
    })]
    fn serialize_deserialize(#[case] st: &str, #[case] origin: Secret) {
        let serialized = serde_json::to_string_pretty(&origin).expect("serialize failed");
        assert_json_eq!(st, serialized);

        let parsed: Secret = serde_json::from_str(st).expect("deserialize failed");
        assert_eq!(parsed, origin);
    }
}
