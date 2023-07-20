// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod layout;

use serde::{Deserialize, Serialize};

use self::layout::{envelope::Envelope, vault::VaultSecret};

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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use assert_json_diff::assert_json_eq;
    use crypto::WrapType;
    use rstest::rstest;

    use crate::secret::layout::{envelope::Envelope, vault::VaultSecret};

    use super::{Secret, SecretContent};

    #[rstest]
    #[case(include_str!("../../test/envelope-1.json"), Secret {
        version: "0.1.0".into(),
        r#type: SecretContent::Envelope(Envelope {
            provider: "ali".into(),
            key_id: "xxx".into(),
            encrypted_key: "yyy".into(),
            encrypted_data: "zzz".into(),
            wrap_type: WrapType::Aes256Gcm,
            iv: "www".into(),
            annotations: HashMap::new(),
        }),
    })]
    #[case(include_str!("../../test/vault-1.json"), Secret {
        version: "0.1.0".into(),
        r#type: SecretContent::Vault(VaultSecret {
            provider: "ali".into(),
            annotations: HashMap::new(),
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
