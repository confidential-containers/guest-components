// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use serde::*;

use crate::SignScheme;
use crate::Image;

/// Policy Requirement Types.
/// * `Accept`: s.t. `insecureAcceptAnything`, skip signature verification, accept the image unconditionally.
/// * `Reject`: s.t. `reject`, reject the image directly.
/// * `SignedBy`: s.t. `signBy`, means that the image is signed by some signing scheme.
/// The member of `SignedBy` here is another enum `SignScheme`. Because each
/// sign scheme may have different json fields in the `policy.json`. So if any
/// new scheme is being added, a new `SignScheme` enum entry should be added, too.
#[derive(Deserialize, Debug, PartialEq, Serialize)]
#[serde(tag = "type")]
pub enum PolicyReqType {
    #[serde(rename = "insecureAcceptAnything")]
    Accept,
    #[serde(rename = "reject")]
    Reject,
    #[serde(rename = "signedBy")]
    SignedBy(SignScheme),
}

impl PolicyReqType {
    /// Check whether an image is allowed by a given policy requirement.
    pub fn allows_image(&self, image: &mut Image) -> Result<()> {
        match self {
            PolicyReqType::Accept => Ok(()),
            PolicyReqType::Reject => Err(anyhow!(r#"The policy is "reject""#)),
            PolicyReqType::SignedBy(scheme) => scheme.allows_image(image),
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::{policy::{PolicyReqType, policy_requirement::SignScheme, ref_match::PolicyReqMatchType}, mechanism::simple::SimpleParameters};

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
                "scheme": "simple",
                "keyType": "GPGKeys",
                "keyPath": "/keys/public-gpg-keyring"
            }"#,
            r#"{
                "type": "signedBy",
                "scheme": "simple",
                "keyType": "GPGKeys",
                "keyData": "bm9uc2Vuc2U="
            }"#,
            r#"{
                "type": "signedBy",
                "scheme": "simple",
                "keyType": "GPGKeys",
                "keyPath": "/keys/public-gpg-keyring",
                "signedIdentity": {
                    "type": "matchExact"
                }
            }"#,
            r#"{
                "type": "signedBy",
                "scheme": "simple",
                "keyType": "GPGKeys",
                "keyPath": "/keys/public-gpg-keyring",
                "signedIdentity": {
                    "type": "exactReference",
                    "dockerReference": "docker.io/example/busybox:latest"
                }
            }"#,
            r#"{
                "type": "signedBy",
                "scheme": "simple",
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
            PolicyReqType::SignedBy(
                SignScheme::SimpleSigning(
                    SimpleParameters {
                        key_type: "GPGKeys".into(),
                        key_path: Some("/keys/public-gpg-keyring".into()),
                        key_data: None,
                        signed_identity: None,
                    }
                )
            ),
            PolicyReqType::SignedBy(
                SignScheme::SimpleSigning(
                    SimpleParameters {
                        key_type: "GPGKeys".into(),
                        key_path: None,
                        key_data: Some("bm9uc2Vuc2U=".into()),
                        signed_identity: None,
                    }
                )
            ),
            PolicyReqType::SignedBy(
                SignScheme::SimpleSigning(
                    SimpleParameters {
                        key_type: "GPGKeys".into(),
                        key_path: Some("/keys/public-gpg-keyring".into()),
                        key_data: None,
                        signed_identity: Some(PolicyReqMatchType::MatchExact),
                    }
                )
            ),
            PolicyReqType::SignedBy(
                SignScheme::SimpleSigning(
                    SimpleParameters {
                        key_type: "GPGKeys".into(),
                        key_path: Some("/keys/public-gpg-keyring".into()),
                        key_data: None,
                        signed_identity: Some(
                            PolicyReqMatchType::ExactReference {
                                docker_reference: "docker.io/example/busybox:latest".into(),
                            }
                        ),
                    }
                )
            ),
            PolicyReqType::SignedBy(
                SignScheme::SimpleSigning(
                    SimpleParameters {
                        key_type: "GPGKeys".into(),
                        key_path: Some("/keys/public-gpg-keyring".into()),
                        key_data: None,
                        signed_identity: Some(
                            PolicyReqMatchType::RemapIdentity {
                                prefix: "example".into(),
                                signed_prefix: "example".into(),
                            }
                        ),
                    }
                )
            ),
        ];

        let policy_parsed: Vec<PolicyReqType> = jsons.iter()
            .map(|json|{
                serde_json::from_str(json).unwrap()
            })
            .collect();
        
        for i in 0..jsons.len() {
            assert_eq!(policies[i], policy_parsed[i]);
        }
    }
}
