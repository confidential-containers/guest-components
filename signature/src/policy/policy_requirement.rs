// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use serde::*;

use crate::{
    image::Image,
    mechanism::{cosign::CosignParameters, simple::SimpleParameters, SignScheme},
};

/// Policy Requirement Types.
/// * `Accept`: s.t. `insecureAcceptAnything`, skip signature verification, accept the image unconditionally.
/// * `Reject`: s.t. `reject`, reject the image directly.
/// * `SignedBy`: s.t. `signBy`, means that the image is signed by `Simple Signing`,
/// and the related parameters are inside the enum.
#[derive(Deserialize, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type")]
pub enum PolicyReqType {
    /// Accept all images
    #[serde(rename = "insecureAcceptAnything")]
    Accept,

    /// Deny all images
    #[serde(rename = "reject")]
    Reject,

    /// Signed by Simple Signing
    #[serde(rename = "signedBy")]
    SimpleSigning(SimpleParameters),

    /// Signed by Cosign
    #[serde(rename = "sigstoreSigned")]
    Cosign(CosignParameters),
    // TODO: Add more signature mechanism.
    //
    // Refer to issue: https://github.com/confidential-containers/image-rs/issues/7
}

impl PolicyReqType {
    /// Check whether an image is allowed by a given policy requirement.
    pub async fn allows_image(&self, image: &mut Image) -> Result<()> {
        match self {
            PolicyReqType::Accept => Ok(()),
            PolicyReqType::Reject => Err(anyhow!(r#"The policy is "reject""#)),
            PolicyReqType::SimpleSigning(inner) => inner.allows_image(image).await,
            PolicyReqType::Cosign(inner) => inner.allows_image(image).await,
        }
    }

    /// Return the `SignScheme` trait object if it is some signing scheme,
    /// or None if not.
    pub fn try_into_sign_scheme(&self) -> Option<&dyn SignScheme> {
        match self {
            PolicyReqType::SimpleSigning(scheme) => Some(scheme as &dyn SignScheme),
            PolicyReqType::Cosign(scheme) => Some(scheme as &dyn SignScheme),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        mechanism::simple::SimpleParameters,
        policy::{ref_match::PolicyReqMatchType, PolicyReqType},
    };

    #[test]
    fn deserialize_accept_policy() {
        let json = r#"{
            "type": "insecureAcceptAnything"
        }"#;
        let policy_parsed: PolicyReqType = serde_json::from_str(json).unwrap();
        let policy = PolicyReqType::Accept;
        assert_eq!(policy, policy_parsed);
    }

    #[test]
    fn deserialize_reject_policy() {
        let json = r#"{
            "type": "reject"
        }"#;
        let policy_parsed: PolicyReqType = serde_json::from_str(json).unwrap();
        let policy = PolicyReqType::Reject;
        assert_eq!(policy, policy_parsed);
    }

    #[test]
    fn deserialize_signed_by_policy() {
        let jsons = [
            r#"{
                "type": "signedBy",
                "keyType": "GPGKeys",
                "keyPath": "/keys/public-gpg-keyring"
            }"#,
            r#"{
                "type": "signedBy",
                "keyType": "GPGKeys",
                "keyData": "bm9uc2Vuc2U="
            }"#,
            r#"{
                "type": "signedBy",
                "keyType": "GPGKeys",
                "keyPath": "/keys/public-gpg-keyring",
                "signedIdentity": {
                    "type": "matchExact"
                }
            }"#,
            r#"{
                "type": "signedBy",
                "keyType": "GPGKeys",
                "keyPath": "/keys/public-gpg-keyring",
                "signedIdentity": {
                    "type": "exactReference",
                    "dockerReference": "docker.io/example/busybox:latest"
                }
            }"#,
            r#"{
                "type": "signedBy",
                "keyType": "GPGKeys",
                "keyPath": "/keys/public-gpg-keyring",
                "signedIdentity": {
                    "type": "remapIdentity",
                    "prefix": "example",
                    "signedPrefix": "example"
                }
            }"#,
        ];
        let policies = [
            PolicyReqType::SimpleSigning(SimpleParameters {
                key_type: "GPGKeys".into(),
                key_path: Some("/keys/public-gpg-keyring".into()),
                key_data: None,
                signed_identity: None,
            }),
            PolicyReqType::SimpleSigning(SimpleParameters {
                key_type: "GPGKeys".into(),
                key_path: None,
                key_data: Some("bm9uc2Vuc2U=".into()),
                signed_identity: None,
            }),
            PolicyReqType::SimpleSigning(SimpleParameters {
                key_type: "GPGKeys".into(),
                key_path: Some("/keys/public-gpg-keyring".into()),
                key_data: None,
                signed_identity: Some(PolicyReqMatchType::MatchExact),
            }),
            PolicyReqType::SimpleSigning(SimpleParameters {
                key_type: "GPGKeys".into(),
                key_path: Some("/keys/public-gpg-keyring".into()),
                key_data: None,
                signed_identity: Some(PolicyReqMatchType::ExactReference {
                    docker_reference: "docker.io/example/busybox:latest".into(),
                }),
            }),
            PolicyReqType::SimpleSigning(SimpleParameters {
                key_type: "GPGKeys".into(),
                key_path: Some("/keys/public-gpg-keyring".into()),
                key_data: None,
                signed_identity: Some(PolicyReqMatchType::RemapIdentity {
                    prefix: "example".into(),
                    signed_prefix: "example".into(),
                }),
            }),
        ];

        let policy_parsed: Vec<PolicyReqType> = jsons
            .iter()
            .map(|json| serde_json::from_str(json).unwrap())
            .collect();

        for i in 0..jsons.len() {
            assert_eq!(policies[i], policy_parsed[i]);
        }
    }
}
