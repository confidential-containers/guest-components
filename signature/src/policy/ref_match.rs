// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use oci_distribution::Reference;
use serde::de::{self, MapAccess, Visitor};
use serde::*;
use serde_json::{Map, Value};
use std::convert::TryFrom;
use std::str::FromStr;

use crate::image;

use crate::policy::ErrorInfo;

#[derive(EnumString, Display, Debug, PartialEq)]
pub enum PolicyReqMatchType {
    #[strum(serialize = "matchExact")]
    TypeMatchExact,
    #[strum(serialize = "matchRepoDigestOrExact")]
    TypeMatchRepoDigestOrExact,
    #[strum(serialize = "matchRepository")]
    TypeMatchRepository,
    #[strum(serialize = "exactReference")]
    TypeExactReference,
    #[strum(serialize = "exactRepository")]
    TypeExactRepository,
    #[strum(serialize = "remapIdentity")]
    TypeRemapIdentity,
}

// PolicyReferenceMatch specifies a set of image identities(image-reference) accepted in PolicyRequirement.
pub trait PolicyReferenceMatcher {
    fn matches_docker_reference(&self, origin: &Reference, signed_image_ref: &str) -> Result<()>;
}

impl<'de> Deserialize<'de> for Box<dyn PolicyReferenceMatcher> {
    fn deserialize<D>(deserializer: D) -> Result<Box<dyn PolicyReferenceMatcher>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(PolicyReferenceMatcherVisitor)
    }
}

struct PolicyReferenceMatcherVisitor;

impl<'de> Visitor<'de> for PolicyReferenceMatcherVisitor {
    type Value = Box<dyn PolicyReferenceMatcher>;

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

        match PolicyReqMatchType::from_str(&r#type) {
            Ok(PolicyReqMatchType::TypeMatchExact) => {
                let res: MatchExact = serde_json::from_str(&json_str).map_err(de::Error::custom)?;
                return Ok(Box::new(res));
            }
            Ok(PolicyReqMatchType::TypeMatchRepoDigestOrExact) => {
                let res: MatchRepoDigestOrExact =
                    serde_json::from_str(&json_str).map_err(de::Error::custom)?;
                return Ok(Box::new(res));
            }
            Ok(PolicyReqMatchType::TypeMatchRepository) => {
                let res: MatchRepository =
                    serde_json::from_str(&json_str).map_err(de::Error::custom)?;
                return Ok(Box::new(res));
            }
            Ok(PolicyReqMatchType::TypeExactReference) => {
                let res: MatchExactReference =
                    serde_json::from_str(&json_str).map_err(de::Error::custom)?;
                return Ok(Box::new(res));
            }
            Ok(PolicyReqMatchType::TypeExactRepository) => {
                let res: MatchExactRepository =
                    serde_json::from_str(&json_str).map_err(de::Error::custom)?;
                return Ok(Box::new(res));
            }
            Ok(PolicyReqMatchType::TypeRemapIdentity) => {
                let res: MatchRemapIdentity =
                    serde_json::from_str(&json_str).map_err(de::Error::custom)?;
                return Ok(Box::new(res));
            }
            _ => {
                return Err(de::Error::custom(
                    &ErrorInfo::ErrUnknownMatchPolicyType.to_string(),
                ));
            }
        }
    }
}

impl TryFrom<&str> for Box<dyn PolicyReferenceMatcher> {
    type Error = serde_json::Error;
    fn try_from(json_str: &str) -> Result<Self, Self::Error> {
        serde_json::from_str::<Box<dyn PolicyReferenceMatcher>>(json_str)
    }
}

// "matchExact" match type : the two references must match exactly.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct MatchExact {
    r#type: String,
}

impl PolicyReferenceMatcher for MatchExact {
    fn matches_docker_reference(&self, origin: &Reference, signed_image_ref: &str) -> Result<()> {
        if origin.digest().is_some() {
            return Err(anyhow!(
                "Can not reference the image with the digest in {} policy.",
                PolicyReqMatchType::TypeMatchExact.to_string()
            ));
        }
        if origin.whole() != *signed_image_ref {
            return Err(anyhow!(ErrorInfo::ErrMatchReference.to_string()));
        }
        Ok(())
    }
}

// "matchRepoDigestOrExact" match type: the two references must match exactly,
// except that digest references are also accepted
// if the repository name matches (regardless of tag/digest)
// and the signature applies to the referenced digest.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct MatchRepoDigestOrExact {
    r#type: String,
}

impl PolicyReferenceMatcher for MatchRepoDigestOrExact {
    fn matches_docker_reference(&self, origin: &Reference, signed_image_ref: &str) -> Result<()> {
        if origin.tag().is_some() && origin.whole() != *signed_image_ref {
            return Err(anyhow!(ErrorInfo::ErrMatchReference.to_string()));
        }
        if origin.digest().is_some()
            && image::get_image_repository_full_name(origin)
                != image::get_image_repository_full_name(&Reference::try_from(signed_image_ref)?)
        {
            return Err(anyhow!(ErrorInfo::ErrMatchReference.to_string()));
        }
        Ok(())
    }
}

// "matchRepository" match type: the two references must use the same repository, may differ in the tag.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct MatchRepository {
    r#type: String,
}

impl PolicyReferenceMatcher for MatchRepository {
    fn matches_docker_reference(&self, origin: &Reference, signed_image_ref: &str) -> Result<()> {
        if image::get_image_repository_full_name(origin)
            != image::get_image_repository_full_name(&Reference::try_from(signed_image_ref)?)
        {
            return Err(anyhow!(ErrorInfo::ErrMatchReference.to_string()));
        }
        Ok(())
    }
}

// Match type: "exactReference".
// matches a specified reference exactly.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct MatchExactReference {
    r#type: String,
    #[serde(rename = "dockerReference")]
    docker_reference: String,
}

impl PolicyReferenceMatcher for MatchExactReference {
    fn matches_docker_reference(
        &self,
        _origin_ref: &Reference,
        signed_image_ref: &str,
    ) -> Result<()> {
        if *signed_image_ref != self.docker_reference {
            return Err(anyhow!(ErrorInfo::ErrMatchReference.to_string()));
        }
        Ok(())
    }
}

// Match type: "exactRepository"
// matches a specified repository, with any tag.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct MatchExactRepository {
    r#type: String,
    #[serde(rename = "dockerRepository")]
    docker_repository: String,
}

impl PolicyReferenceMatcher for MatchExactRepository {
    fn matches_docker_reference(
        &self,
        _origin_ref: &Reference,
        signed_image_ref: &str,
    ) -> Result<()> {
        if image::get_image_repository_full_name(&Reference::try_from(signed_image_ref)?)
            != self.docker_repository
        {
            return Err(anyhow!(ErrorInfo::ErrMatchReference.to_string()));
        }
        Ok(())
    }
}

// Match type: "remapIdentity"
// except that a namespace (at least a host:port, at most a single repository)
// is substituted before matching the two references.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct MatchRemapIdentity {
    r#type: String,
    prefix: String,
    #[serde(rename = "signedPrefix")]
    signed_prefix: String,
}

impl PolicyReferenceMatcher for MatchRemapIdentity {
    fn matches_docker_reference(
        &self,
        origin_ref: &Reference,
        signed_image_ref: &str,
    ) -> Result<()> {
        let mut origin_ref_string = origin_ref.whole();

        if let Some(ref_with_no_prefix) = origin_ref_string.strip_prefix(&self.prefix) {
            origin_ref_string = format!("{}{}", &self.signed_prefix, ref_with_no_prefix);
        }

        let new_origin_ref = Reference::try_from(origin_ref_string.as_str())?;

        if new_origin_ref.tag().is_some() && new_origin_ref.whole() != *signed_image_ref {
            return Err(anyhow!(ErrorInfo::ErrMatchReference.to_string()));
        }
        if new_origin_ref.digest().is_some()
            && image::get_image_repository_full_name(&new_origin_ref)
                != image::get_image_repository_full_name(&Reference::try_from(signed_image_ref)?)
        {
            return Err(anyhow!(ErrorInfo::ErrMatchReference.to_string()));
        }
        Ok(())
    }
}

pub fn default_match_policy() -> Box<dyn PolicyReferenceMatcher> {
    Box::new(MatchExact {
        r#type: PolicyReqMatchType::TypeMatchExact.to_string(),
    })
}

mod tests {

    #[test]
    fn test_policy_matches_docker_reference() {
        struct TestData<'a> {
            match_policy: Box<dyn super::PolicyReferenceMatcher>,
            origin_reference: oci_distribution::Reference,
            signed_reference: &'a str,
        }

        let tests_expect = &[
            TestData {
                match_policy: serde_json::from_str::<Box<dyn super::PolicyReferenceMatcher>>(
                    r#"{
                        "type": "matchExact"
                    }"#
                ).unwrap(),
                origin_reference: oci_distribution::Reference::try_from("docker.io/example/busybox:latest").unwrap(),
                signed_reference: "docker.io/example/busybox:latest",
            },
            TestData {
                match_policy: serde_json::from_str::<Box<dyn super::PolicyReferenceMatcher>>(
                    r#"{
                        "type": "matchRepoDigestOrExact"
                    }"#
                ).unwrap(),
                origin_reference: oci_distribution::Reference::try_from("docker.io/example/busybox:latest").unwrap(),
                signed_reference: "docker.io/example/busybox:latest",
            },
            TestData {
                match_policy: serde_json::from_str::<Box<dyn super::PolicyReferenceMatcher>>(
                    r#"{
                        "type": "matchRepoDigestOrExact"
                    }"#
                ).unwrap(),
                origin_reference: oci_distribution::Reference::try_from(
                    "docker.io/example/busybox@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                ).unwrap(),
                signed_reference: "docker.io/example/busybox:tag",
            },
            TestData {
                match_policy: serde_json::from_str::<Box<dyn super::PolicyReferenceMatcher>>(
                    r#"{
                        "type": "matchRepository"
                    }"#
                ).unwrap(),
                origin_reference: oci_distribution::Reference::try_from("docker.io/example/busybox:latest").unwrap(),
                signed_reference: "docker.io/example/busybox:tag",
            },
            TestData {
                match_policy: serde_json::from_str::<Box<dyn super::PolicyReferenceMatcher>>(
                    r#"{
                        "type": "exactReference",
                        "dockerReference": "docker.io/mylib/busybox:latest"
                    }"#
                ).unwrap(),
                origin_reference: oci_distribution::Reference::try_from("docker.io/example/busybox:latest").unwrap(),
                signed_reference: "docker.io/mylib/busybox:latest",
            },
            TestData {
                match_policy: serde_json::from_str::<Box<dyn super::PolicyReferenceMatcher>>(
                    r#"{
                        "type": "exactRepository",
                        "dockerRepository": "docker.io/mylib/busybox"
                    }"#
                ).unwrap(),
                origin_reference: oci_distribution::Reference::try_from("docker.io/example/busybox:latest").unwrap(),
                signed_reference: "docker.io/mylib/busybox:tag",
            },
            TestData {
                match_policy: serde_json::from_str::<Box<dyn super::PolicyReferenceMatcher>>(
                    r#"{
                        "type": "remapIdentity",
                        "prefix": "docker.io",
                        "signedPrefix": "quay.io"
                    }"#
                ).unwrap(),
                origin_reference: oci_distribution::Reference::try_from("docker.io/example/busybox:latest").unwrap(),
                signed_reference: "quay.io/example/busybox:latest",
            },
        ];

        let tests_unexpect = &[
            TestData {
                match_policy: serde_json::from_str::<Box<dyn super::PolicyReferenceMatcher>>(
                    r#"{
                        "type": "matchExact"
                    }"#
                ).unwrap(),
                origin_reference: oci_distribution::Reference::try_from("docker.io/example/busybox:latest").unwrap(),
                signed_reference: "docker.io/example/busybox:tag",
            },
            TestData {
                match_policy: serde_json::from_str::<Box<dyn super::PolicyReferenceMatcher>>(
                    r#"{
                        "type": "matchExact"
                    }"#
                ).unwrap(),
                origin_reference: oci_distribution::Reference::try_from(
                    "docker.io/example/busybox@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                ).unwrap(),
                signed_reference: "docker.io/example/busybox@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            },
            TestData {
                match_policy: serde_json::from_str::<Box<dyn super::PolicyReferenceMatcher>>(
                    r#"{
                        "type": "matchRepoDigestOrExact"
                    }"#
                ).unwrap(),
                origin_reference: oci_distribution::Reference::try_from("docker.io/example/busybox:latest").unwrap(),
                signed_reference: "docker.io/example/busybox:tag",
            },
            TestData {
                match_policy: serde_json::from_str::<Box<dyn super::PolicyReferenceMatcher>>(
                    r#"{
                        "type": "exactReference",
                        "dockerReference": "docker.io/mylib/busybox:latest"
                    }"#
                ).unwrap(),
                origin_reference: oci_distribution::Reference::try_from("docker.io/example/busybox:latest").unwrap(),
                signed_reference: "docker.io/example/busybox:latest",
            },
        ];

        for test_case in tests_expect.iter() {
            assert!(test_case
                .match_policy
                .matches_docker_reference(&test_case.origin_reference, test_case.signed_reference)
                .is_ok());
        }

        for test_case in tests_unexpect.iter() {
            assert!(test_case
                .match_policy
                .matches_docker_reference(&test_case.origin_reference, test_case.signed_reference)
                .is_err());
        }
    }
}
