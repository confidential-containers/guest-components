// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use serde::de::{self, MapAccess, Visitor};
use serde::*;
use serde_json::{Map, Value};
use std::convert::TryFrom;
use std::fs;
use std::str::FromStr;
use std::vec::Vec;

use crate::image;
use crate::signatures;

use crate::policy::ref_match::PolicyReferenceMatcher;
use crate::policy::ErrorInfo;

#[derive(EnumString, Display, Debug, PartialEq)]
pub enum PolicyReqType {
    #[strum(to_string = "insecureAcceptAnything")]
    TypeAccept,
    #[strum(to_string = "reject")]
    TypeReject,
    #[strum(to_string = "signedBy")]
    TypeSignedBy,
}

#[derive(EnumString, Display, Debug, PartialEq)]
pub enum KeyType {
    #[strum(to_string = "GPGKeys")]
    Gpg,
}

// Policy requirement is a rule which must be satisfied by the image.
// It has three types:
//   `insecureAcceptAnything`: skip signature verification, accept the image unconditionally.
//   `reject`: reject the image directly.
//   `signedBy`: there must be at least a signature of the image can be verified by the specific key.
pub trait PolicyRequirement {
    fn is_image_allowed(&self, image: &mut image::Image) -> Result<()>;
}

impl<'de> Deserialize<'de> for Box<dyn PolicyRequirement> {
    fn deserialize<D>(deserializer: D) -> Result<Box<dyn PolicyRequirement>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(PolicyRequirementVisitor)
    }
}

struct PolicyRequirementVisitor;

impl<'de> Visitor<'de> for PolicyRequirementVisitor {
    type Value = Box<dyn PolicyRequirement>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("Unexpect policy requirement deserialize visit format")
    }

    #[allow(unused_assignments)]
    fn visit_map<A>(self, mut json_map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut map = Map::new();
        loop {
            if let Result::Ok(Some(entry)) = json_map.next_entry::<String, Value>() {
                map.insert(entry.0.into(), entry.1.into());
            } else {
                break;
            }
        }

        let v: Value = map.into();
        let json_str = serde_json::to_string(&v).map_err(de::Error::custom)?;

        let mut r#type = String::new();
        if let Value::String(s) = &v["type"] {
            r#type = s.to_string();
        } else {
            return Err(de::Error::custom(
                &ErrorInfo::ErrUnknownMatchPolicyType.to_string(),
            ));
        }

        match PolicyReqType::from_str(&r#type) {
            Ok(PolicyReqType::TypeAccept) => {
                let res: PolicyReqAccept =
                    serde_json::from_str(&json_str).map_err(de::Error::custom)?;
                return Ok(Box::new(res));
            }
            Ok(PolicyReqType::TypeReject) => {
                let res: PolicyReqReject =
                    serde_json::from_str(&json_str).map_err(de::Error::custom)?;
                return Ok(Box::new(res));
            }
            Ok(PolicyReqType::TypeSignedBy) => {
                let res: PolicyReqSignedBy =
                    serde_json::from_str(&json_str).map_err(de::Error::custom)?;
                return Ok(Box::new(res));
            }
            _ => {
                return Err(de::Error::custom(
                    &ErrorInfo::ErrUnknowPolicyReqType.to_string(),
                ));
            }
        }
    }
}

impl TryFrom<&str> for Box<dyn PolicyRequirement> {
    type Error = serde_json::Error;
    fn try_from(json_str: &str) -> Result<Self, Self::Error> {
        serde_json::from_str::<Box<dyn PolicyRequirement>>(json_str)
    }
}

// The `insecureAcceptAnything` policy requirement.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct PolicyReqAccept {
    r#type: String,
}

impl PolicyRequirement for PolicyReqAccept {
    fn is_image_allowed(&self, _image: &mut image::Image) -> Result<()> {
        Ok(())
    }
}

// The `insecureAcceptAnything` policy requirement.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct PolicyReqReject {
    r#type: String,
}

impl PolicyRequirement for PolicyReqReject {
    fn is_image_allowed(&self, _image: &mut image::Image) -> Result<()> {
        Err(anyhow!(r#"The policy is "reject""#))
    }
}

// The `signedBy` policy requirement:
// The image must be signed by trusted keys for a specified identity
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct PolicyReqSignedBy {
    r#type: String,

    // KeyType specifies what kind of key reference KeyPath/KeyData is.
    // Acceptable values are "GPGKeys" | "signedByGPGKeys” "X.509Certificates" | "signedByX.509CAs"
    // FIXME: now only support "GPGKeys", fllowing the [containers/image](https://github.com/containers/image)
    #[serde(rename = "keyType")]
    key_type: String,

    // KeyPath is a pathname to a local file containing the trusted key(s).
    // Exactly one of KeyPath and KeyData must be specified.
    #[serde(default, rename = "keyPath")]
    key_path: String,
    // KeyData contains the trusted key(s), base64-encoded.
    // Exactly one of KeyPath and KeyData must be specified.
    #[serde(default, rename = "keyData")]
    key_data: String,

    // SignedIdentity specifies what image identity the signature must be claiming about the image.
    // Defaults to "match-exact" if not specified.
    #[serde(default, rename = "signedIdentity")]
    signed_identity: Option<Box<dyn PolicyReferenceMatcher>>,
}

impl PolicyRequirement for PolicyReqSignedBy {
    fn is_image_allowed(&self, image: &mut image::Image) -> Result<()> {
        let sigs = image.signatures()?;
        if sigs.is_empty() {
            return Err(anyhow!("Can not find any signatures."));
        }

        let mut reject_reason: Vec<anyhow::Error> = Vec::new();

        for sig in sigs.iter() {
            match self.is_signature_valid(image, sig.to_vec()) {
                // One accepted signature is enough.
                Ok(()) => {
                    return Ok(());
                }
                Err(e) => {
                    reject_reason.push(e);
                }
            }
        }

        Err(anyhow!(format!(
            "The signatures do not satisfied! Reject reason: {:?}",
            reject_reason
        )))
    }
}

impl PolicyReqSignedBy {
    #[allow(unused_assignments)]
    fn is_signature_valid(&self, image: &image::Image, sig: Vec<u8>) -> Result<()> {
        // FIXME: only support "GPGKeys" type now.
        //
        // refer to https://github.com/confidential-containers/image-rs/issues/14
        if self.key_type != KeyType::Gpg.to_string() {
            return Err(anyhow!(
                "Unknown key type in policy config: only support {} now.",
                KeyType::Gpg.to_string()
            ));
        }

        if !self.key_path.is_empty() && !self.key_data.is_empty() {
            return Err(anyhow!("Both keyPath and keyData specified."));
        }

        let pubkey_ring = if !self.key_data.is_empty() {
            base64::decode(&self.key_data)?
        } else {
            fs::read(&self.key_path)?
        };

        // TODO: Verify the signature with the pubkey ring.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Image;
    use crate::Policy;
    use oci_distribution::Reference;
    use std::env;

    #[test]
    fn test_pr_signedby_signature_judge_allowed() {
        let pr_signedby_json = r#"{
            "type": "signedBy",
            "keyType": "GPGKeys",
            "keyPath": "fixtures/pubring.gpg"
        }"#;
        let pr_signedby: PolicyReqSignedBy =
            serde_json::from_str::<PolicyReqSignedBy>(pr_signedby_json).unwrap();

        let reference = Reference::try_from("quay.io/ali_os_security/alpine:latest").unwrap();
        let mut image = Image::default_with_reference(reference);
        image
            .set_manifest_digest(
                "sha256:69704ef328d05a9f806b6b8502915e6a0a4faa4d72018dc42343f511490daf8a",
            )
            .expect("digest format error");

        let current_dir = env::current_dir().expect("not found path");
        let test_sigstore_dir =
            format!("file://{}/fixtures/sigstore", current_dir.to_str().unwrap());
        image
            .set_sigstore_base_url(test_sigstore_dir.to_string())
            .expect("digest format error");

        assert!(pr_signedby.is_image_allowed(&mut image).is_ok());
    }

    #[test]
    fn test_pr_simple_judge_allowed() {
        let policy = Policy::from_file("./fixtures/policy.json").unwrap();

        let tests_accept = &["example.com/playground/busybox:latest"];

        let tests_reject = &[
            "test:5000/library/busybox:latest",
            "default/library/repo:tag",
        ];

        for case in tests_accept {
            let reference = Reference::try_from(*case).expect("could not parse reference");
            let image = image::Image::default_with_reference(reference);
            assert!(policy.is_image_allowed(image).is_ok());
        }

        for case in tests_reject {
            let reference = Reference::try_from(*case).expect("could not parse reference");
            let image = image::Image::default_with_reference(reference);
            assert!(policy.is_image_allowed(image).is_err());
        }
    }
}
