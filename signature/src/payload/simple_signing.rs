// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Payload format of simple signing

use anyhow::{anyhow, Result};
use oci_distribution::Reference;
use serde::{Deserialize, Serialize};

use crate::policy::ref_match::PolicyReqMatchType;

// The spec of SigPayload is defined in https://github.com/containers/image/blob/main/docs/containers-signature.5.md.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SigPayload {
    #[serde(flatten)]
    inner: sigstore_rs::simple_signing::SimpleSigning,
}

impl SigPayload {
    // Compare wether the docker reference in the JSON payload
    // is consistent with that of the container image.
    pub fn validate_signed_docker_reference(
        &self,
        image_ref: &Reference,
        match_policy: &PolicyReqMatchType,
    ) -> Result<()> {
        match_policy.matches_docker_reference(image_ref, &self.docker_reference())
    }

    // Compare wether the manifest digest in the JSON payload
    // is consistent with that of the container image.
    pub fn validate_signed_docker_manifest_digest(&self, ref_manifest_digest: &str) -> Result<()> {
        if self.manifest_digest() != ref_manifest_digest {
            return Err(anyhow!(
                "SigPayload's manifest digest does not match, the input is {}, but in SigPayload it is {}",
                &ref_manifest_digest,
                &self.manifest_digest()
            ));
        }
        Ok(())
    }

    fn manifest_digest(&self) -> String {
        self.inner.critical.image.docker_manifest_digest.clone()
    }

    fn docker_reference(&self) -> String {
        self.inner.critical.identity.docker_reference.clone()
    }
}

// A JSON object which contains data critical to correctly evaluating the validity of a signature.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct SigPayloadCritical {
    r#type: String,
    pub image: PayloadCriticalImage,
    pub identity: PayloadCriticalIdentity,
}

// A JSON object which identifies the container image this signature applies to.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct PayloadCriticalImage {
    // A JSON string, in the github.com/opencontainers/go-digest.Digest string format.
    #[serde(rename = "docker-manifest-digest")]
    pub docker_manifest_digest: String,
}

// A JSON object which identifies the claimed identity of the image
// (usually the purpose of the image, or the application, along with a version information),
// as asserted by the author of the signature.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct PayloadCriticalIdentity {
    // A JSON string, in the github.com/docker/distribution/reference string format,
    // and using the same normalization semantics
    // (where e.g. busybox:latest is equivalent to docker.io/library/busybox:latest).
    // If the normalization semantics allows multiple string representations
    // of the claimed identity with equivalent meaning,
    // the critical.identity.docker-reference member SHOULD use the fully explicit form
    // (including the full host name and namespaces).
    #[serde(rename = "docker-reference")]
    pub docker_reference: String,
}

impl From<sigstore_rs::simple_signing::SimpleSigning> for SigPayload {
    fn from(ori: sigstore_rs::simple_signing::SimpleSigning) -> Self {
        Self { inner: ori }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::SigPayload;

    #[test]
    fn serialize_simple_signing_payload() {
        let json = json!({
            "critical": {
                "identity": {
                    "docker-reference": "quay.io/ali_os_security/alpine:latest"
                },
                  "image": {
                    "docker-manifest-digest": "sha256:69704ef328d05a9f806b6b8502915e6a0a4faa4d72018dc42343f511490daf8a"
                },
                  "type": "atomic container signature"
            },
            "optional": {
                "creator": "atomic 2.0.0",
                "timestamp": 1634533638
            }
        });

        let payload = SigPayload {
            inner: sigstore_rs::simple_signing::SimpleSigning {
                critical: sigstore_rs::simple_signing::Critical {
                    type_name: "atomic container signature".into(),
                    image: sigstore_rs::simple_signing::Image {
                        docker_manifest_digest: "sha256:69704ef328d05a9f806b6b8502915e6a0a4faa4d72018dc42343f511490daf8a".into(),
                    },
                    identity: sigstore_rs::simple_signing::Identity {
                        docker_reference: "quay.io/ali_os_security/alpine:latest".into(),
                    },
                },
                optional: Some(sigstore_rs::simple_signing::Optional {
                    creator: Some("atomic 2.0.0".into()),
                    timestamp: Some(1634533638),
                    extra: HashMap::new(),
                }),
            },
        };

        let payload_serialize = serde_json::to_value(&payload).unwrap();
        assert_eq!(payload_serialize, json);
    }

    #[test]
    fn deserialize_simple_signing_payload() {
        let json = r#"{
            "critical": {
                "identity": {
                    "docker-reference": "quay.io/ali_os_security/alpine:latest"
                },
                  "image": {
                    "docker-manifest-digest": "sha256:69704ef328d05a9f806b6b8502915e6a0a4faa4d72018dc42343f511490daf8a"
                },
                  "type": "atomic container signature"
            },
            "optional": {
                "creator": "atomic 2.0.0",
                "timestamp": 1634533638
            }
        }"#;

        // Because the `PartialEq` trait is not derived, we can only do the
        // comparation one by one.
        let deserialized_payload: SigPayload = serde_json::from_str(json).unwrap();
        assert_eq!(
            deserialized_payload
                .inner
                .critical
                .identity
                .docker_reference,
            "quay.io/ali_os_security/alpine:latest"
        );
        assert_eq!(
            deserialized_payload
                .inner
                .critical
                .image
                .docker_manifest_digest,
            "sha256:69704ef328d05a9f806b6b8502915e6a0a4faa4d72018dc42343f511490daf8a"
        );
        assert_eq!(
            deserialized_payload.inner.critical.type_name,
            "atomic container signature"
        );
        assert_eq!(
            deserialized_payload
                .inner
                .optional
                .as_ref()
                .unwrap()
                .creator,
            Some("atomic 2.0.0".into())
        );
        assert_eq!(
            deserialized_payload
                .inner
                .optional
                .as_ref()
                .unwrap()
                .timestamp,
            Some(1634533638)
        );
        assert_eq!(
            deserialized_payload.inner.optional.as_ref().unwrap().extra,
            HashMap::new()
        );
    }
}
