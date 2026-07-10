// Copyright (c) 2026 Confidential Containers Authors
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Serialized [`crate::ProviderSettings`] for the AWS provider.
///
/// The region is the only piece of public information required to reconstruct a
/// client on the decryptor/getter side. Key material (KMS key ARN/alias) and the
/// secret name are carried out-of-band in the envelope/vault `key_id`/`name`
/// fields respectively.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AwsProviderSettings {
    pub region: String,
}

/// Serialized [`crate::Annotations`] for AWS KMS envelope encryption/decryption.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AwsCryptAnnotations {
    /// Optional AWS KMS [encryption context][ctx] (additional authenticated
    /// data). If present at encryption time it must be presented verbatim at
    /// decryption time, otherwise KMS rejects the request.
    ///
    /// [ctx]: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub encryption_context: HashMap<String, String>,
}

/// Serialized [`crate::Annotations`] for AWS Secrets Manager `GetSecretValue`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AwsSecretAnnotations {
    /// Optional specific version id of the secret. Empty means the current
    /// version (as selected by `version_stage`).
    #[serde(default)]
    pub version_id: String,

    /// Optional staging label of the secret version. Empty lets AWS default to
    /// `AWSCURRENT`.
    #[serde(default)]
    pub version_stage: String,
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::{json, Value};

    use super::{AwsCryptAnnotations, AwsProviderSettings, AwsSecretAnnotations};

    #[test]
    fn provider_settings_round_trip() {
        let settings = AwsProviderSettings {
            region: "us-east-1".to_string(),
        };
        let value = serde_json::to_value(&settings).unwrap();
        assert_eq!(value, json!({ "region": "us-east-1" }));

        let parsed: AwsProviderSettings = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.region, "us-east-1");
    }

    /// Serialization must drop an empty encryption context (so a plain encrypt
    /// yields `{}`) but preserve a populated one verbatim.
    #[rstest]
    #[case::empty(&[], json!({}))]
    #[case::with_context(&[("purpose", "cdh")], json!({ "encryption_context": { "purpose": "cdh" } }))]
    fn crypt_annotations_serialize(#[case] entries: &[(&str, &str)], #[case] expected: Value) {
        let mut annotations = AwsCryptAnnotations::default();
        for (k, v) in entries {
            annotations
                .encryption_context
                .insert(k.to_string(), v.to_string());
        }
        assert_eq!(serde_json::to_value(&annotations).unwrap(), expected);
    }

    /// Ciphertext sealed without an encryption context carries an empty
    /// annotations object; a populated one must round-trip its entries.
    #[rstest]
    #[case::missing(json!({}), &[])]
    #[case::with_context(json!({ "encryption_context": { "purpose": "cdh" } }), &[("purpose", "cdh")])]
    fn crypt_annotations_deserialize(#[case] value: Value, #[case] expected: &[(&str, &str)]) {
        let parsed: AwsCryptAnnotations = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.encryption_context.len(), expected.len());
        for (k, v) in expected {
            assert_eq!(parsed.encryption_context.get(*k).unwrap(), v);
        }
    }

    /// Both secret-version fields always serialize (no skip), so defaults emit
    /// empty strings and explicit values round-trip unchanged.
    #[rstest]
    #[case::default(AwsSecretAnnotations::default(), "", "")]
    #[case::with_values(
        AwsSecretAnnotations {
            version_id: "v-123".to_string(),
            version_stage: "AWSCURRENT".to_string(),
        },
        "v-123",
        "AWSCURRENT"
    )]
    fn secret_annotations_round_trip(
        #[case] annotations: AwsSecretAnnotations,
        #[case] version_id: &str,
        #[case] version_stage: &str,
    ) {
        let value: Value = serde_json::to_value(&annotations).unwrap();
        assert_eq!(
            value,
            json!({ "version_id": version_id, "version_stage": version_stage })
        );

        let parsed: AwsSecretAnnotations = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.version_id, version_id);
        assert_eq!(parsed.version_stage, version_stage);
    }

    /// Missing fields fall back to their defaults thanks to `#[serde(default)]`.
    #[rstest]
    #[case::empty(json!({}), "", "")]
    #[case::partial(json!({ "version_stage": "AWSPREVIOUS" }), "", "AWSPREVIOUS")]
    fn secret_annotations_deserialize_partial(
        #[case] value: Value,
        #[case] version_id: &str,
        #[case] version_stage: &str,
    ) {
        let parsed: AwsSecretAnnotations = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.version_id, version_id);
        assert_eq!(parsed.version_stage, version_stage);
    }
}
