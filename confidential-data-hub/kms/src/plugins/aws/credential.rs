// Copyright (c) 2026 Confidential Containers Authors
//
// SPDX-License-Identifier: Apache-2.0
//

//! Static IAM credentials used to access AWS KMS and Secrets Manager.
//!
//! These are private parameters and, per the [`crate::api`] contract, are read
//! from the guest's encrypted filesystem rather than passed through
//! [`crate::ProviderSettings`]. The expected on-disk format is a JSON document:
//!
//! ```json
//! {
//!   "access_key_id": "AKIA...",
//!   "secret_access_key": "...",
//!   "session_token": null
//! }
//! ```

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct AwsCredential {
    pub access_key_id: String,
    pub secret_access_key: String,

    /// Optional session token for temporary (STS) credentials.
    #[serde(default)]
    pub session_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::AwsCredential;

    #[test]
    fn parse_static_credential_without_session_token() {
        let json = r#"{
            "access_key_id": "AKIAEXAMPLE",
            "secret_access_key": "secret"
        }"#;
        let credential: AwsCredential = serde_json::from_str(json).unwrap();
        assert_eq!(credential.access_key_id, "AKIAEXAMPLE");
        assert_eq!(credential.secret_access_key, "secret");
        assert!(credential.session_token.is_none());
    }

    #[test]
    fn parse_temporary_credential_with_session_token() {
        let json = r#"{
            "access_key_id": "ASIAEXAMPLE",
            "secret_access_key": "secret",
            "session_token": "token"
        }"#;
        let credential: AwsCredential = serde_json::from_str(json).unwrap();
        assert_eq!(credential.session_token.as_deref(), Some("token"));
    }

    #[test]
    fn parse_credential_with_explicit_null_session_token() {
        let json = r#"{
            "access_key_id": "AKIAEXAMPLE",
            "secret_access_key": "secret",
            "session_token": null
        }"#;
        let credential: AwsCredential = serde_json::from_str(json).unwrap();
        assert!(credential.session_token.is_none());
    }

    #[test]
    fn parse_credential_missing_required_field_fails() {
        let json = r#"{ "access_key_id": "AKIAEXAMPLE" }"#;
        assert!(serde_json::from_str::<AwsCredential>(json).is_err());
    }
}
