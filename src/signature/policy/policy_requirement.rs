// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use oci_distribution::secrets::RegistryAuth;
use serde::*;

#[cfg(feature = "cosign")]
use crate::signature::{
    image::Image,
    mechanism::{cosign::CosignParameters, simple::SimpleParameters, SignScheme},
};

#[cfg(not(feature = "cosign"))]
use crate::signature::{
    image::Image,
    mechanism::{simple::SimpleParameters, SignScheme},
    policy::ref_match::PolicyReqMatchType,
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

/// Copy cosign parameters struct from mechansim/cosign/mod.rs when image-rs isn't
/// built with the cosign module
#[cfg(not(feature = "cosign"))]
#[derive(Deserialize, Debug, Eq, PartialEq, Serialize, Default)]
pub struct CosignParameters {
    // KeyPath is a pathname to a local file containing the trusted key(s).
    // Exactly one of KeyPath and KeyData can be specified.
    //
    // This field is optional.
    #[serde(rename = "keyPath")]
    pub key_path: Option<String>,
    // KeyData contains the trusted key(s), base64-encoded.
    // Exactly one of KeyPath and KeyData can be specified.
    //
    // This field is optional.
    #[serde(rename = "keyData")]
    pub key_data: Option<String>,

    // SignedIdentity specifies what image identity the signature must be claiming about the image.
    // Defaults to "match-exact" if not specified.
    //
    // This field is optional.
    #[serde(default, rename = "signedIdentity")]
    pub signed_identity: Option<PolicyReqMatchType>,
}

impl PolicyReqType {
    /// Check whether an image is allowed by a given policy requirement.
    pub async fn allows_image(&self, image: &mut Image, auth: &RegistryAuth) -> Result<()> {
        // On big endian targets such as the s390x architecture, the cosign feature needs
        // to be disabled because the ring crate pulled in by the sigstore-rs crate does not
        // support compiling on big-endian targets. There is an issue open to add
        // big-endian support to ring here: https://github.com/briansmith/ring/issues/1555
        match self {
            PolicyReqType::Accept => Ok(()),
            PolicyReqType::Reject => Err(anyhow!(r#"The policy is "reject""#)),
            PolicyReqType::SimpleSigning(inner) => inner.allows_image(image, auth).await,
            #[cfg(feature = "cosign")]
            PolicyReqType::Cosign(inner) => inner.allows_image(image, auth).await,
            #[cfg(not(feature = "cosign"))]
            PolicyReqType::Cosign(inner) => Err(anyhow!(
                r#"image-rs was built without support for cosign image signing"#
            )),
        }
    }

    /// Return the `SignScheme` trait object if it is some signing scheme,
    /// or None if not.
    pub fn try_into_sign_scheme(&self) -> Option<&dyn SignScheme> {
        match self {
            PolicyReqType::SimpleSigning(scheme) => Some(scheme as &dyn SignScheme),
            #[cfg(feature = "cosign")]
            PolicyReqType::Cosign(scheme) => Some(scheme as &dyn SignScheme),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::signature::{
        mechanism::simple::SimpleParameters,
        policy::{policy_requirement::PolicyReqType, ref_match::PolicyReqMatchType},
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
