// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use serde::de::{self, MapAccess, Visitor};
use serde::*;
use serde_json::{Map, Value};
use std::convert::TryFrom;
use std::str::FromStr;

use crate::image;
use crate::mechanism;

use crate::policy::ref_match::PolicyReferenceMatcher;
use crate::policy::ErrorInfo;
use crate::SignatureScheme;

#[derive(EnumString, Display, Debug, PartialEq)]
pub enum PolicyReqType {
    #[strum(to_string = "insecureAcceptAnything")]
    TypeAccept,
    #[strum(to_string = "reject")]
    TypeReject,
    #[strum(to_string = "signedBy")]
    TypeSignedBy,
}

// Policy requirement is a rule which must be satisfied by the image.
// It has three types:
//   `insecureAcceptAnything`: skip signature verification, accept the image unconditionally.
//   `reject`: reject the image directly.
//   `signedBy`: there must be at least a signature of the image can be verified by the specific key.
pub trait PolicyRequirement {
    fn is_image_allowed(&self, image: &mut image::Image) -> Result<()>;
    fn signature_scheme(&self) -> Option<String> {
        None
    }
}

impl<'de> Deserialize<'de> for Box<dyn PolicyRequirement + Send> {
    fn deserialize<D>(deserializer: D) -> Result<Box<dyn PolicyRequirement + Send>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(PolicyRequirementVisitor)
    }
}

struct PolicyRequirementVisitor;

impl<'de> Visitor<'de> for PolicyRequirementVisitor {
    type Value = Box<dyn PolicyRequirement + Send>;

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

impl TryFrom<&str> for Box<dyn PolicyRequirement + Send> {
    type Error = serde_json::Error;
    fn try_from(json_str: &str) -> Result<Self, Self::Error> {
        serde_json::from_str::<Box<dyn PolicyRequirement + Send>>(json_str)
    }
}

// The `insecureAcceptAnything` policy requirement.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct PolicyReqAccept {
    r#type: String,
}

unsafe impl Send for PolicyReqAccept {}

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

unsafe impl Send for PolicyReqReject {}

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

    // scheme specifies the scheme used to verify the signature.
    // This field is the basis for selecting an appropriate mechanism for signature verification.
    pub scheme: String,

    // KeyType specifies what kind of the public key to verify the signatures.
    #[serde(rename = "keyType")]
    pub key_type: String,

    // KeyPath is a pathname to a local file containing the trusted key(s).
    // Exactly one of KeyPath and KeyData can be specified.
    //
    // This field is optional.
    #[serde(default, rename = "keyPath")]
    pub key_path: String,
    // KeyData contains the trusted key(s), base64-encoded.
    // Exactly one of KeyPath and KeyData can be specified.
    //
    // This field is optional.
    #[serde(default, rename = "keyData")]
    pub key_data: String,

    // SignedIdentity specifies what image identity the signature must be claiming about the image.
    // Defaults to "match-exact" if not specified.
    //
    // This field is optional.
    #[serde(default, rename = "signedIdentity")]
    pub signed_identity: Option<Box<dyn PolicyReferenceMatcher>>,
}

unsafe impl Send for PolicyReqSignedBy {}

impl PolicyRequirement for PolicyReqSignedBy {
    fn is_image_allowed(&self, image: &mut image::Image) -> Result<()> {
        match SignatureScheme::from_str(&self.scheme) {
            Ok(SignatureScheme::SimpleSigning) => {
                return mechanism::simple::judge_signatures_accept(self.clone(), image);
            }
            // TODO: Add more signature mechanism.
            //
            // Refer to issue: https://github.com/confidential-containers/image-rs/issues/7
            _ => Err(anyhow!(ErrorInfo::ErrUnknownScheme.to_string())),
        }
    }

    fn signature_scheme(&self) -> Option<String> {
        Some(self.scheme.clone())
    }
}
