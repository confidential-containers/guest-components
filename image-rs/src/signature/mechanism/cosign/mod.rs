// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Cosign verification

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use oci_distribution::secrets::RegistryAuth;
use serde::{Deserialize, Serialize};

#[cfg(feature = "signature-cosign")]
use sigstore::{
    cosign::{
        verification_constraint::{PublicKeyVerifier, VerificationConstraintVec},
        verify_constraints, ClientBuilder, CosignCapabilities,
    },
    crypto::SigningScheme,
    errors::SigstoreVerifyConstraintsError,
    registry::{Auth, OciReference},
};
use std::str::FromStr;

use super::SignScheme;
use crate::resource;
use crate::signature::{
    image::Image, mechanism::Paths, payload::simple_signing::SigPayload,
    policy::ref_match::PolicyReqMatchType,
};

/// The name of resource to request cosign verification key from kbs
pub const COSIGN_KEY_KBS: &str = "Cosign Key";

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

#[async_trait]
impl SignScheme for CosignParameters {
    /// This initialization will:
    /// * Create [`COSIGN_KEY_DIR`] if not exist.
    #[cfg(feature = "signature-cosign")]
    async fn init(&mut self, _config: &Paths) -> Result<()> {
        Ok(())
    }

    #[cfg(not(feature = "signature-cosign"))]
    async fn init(&mut self, _config: &Paths) -> Result<()> {
        Ok(())
    }

    /// Judge whether an image is allowed by this SignScheme.
    #[cfg(feature = "signature-cosign")]
    async fn allows_image(&self, image: &mut Image, auth: &RegistryAuth) -> Result<()> {
        // Check before we access the network
        self.check_reference_rule_types()?;

        // Verification, will access the network
        let payloads = self.verify_signature_and_get_payload(image, auth).await?;

        // check the reference rules (signed identity)
        for payload in payloads {
            if let Some(rule) = &self.signed_identity {
                payload.validate_signed_docker_reference(&image.reference, rule)?;
            }

            payload.validate_signed_docker_manifest_digest(&image.manifest_digest.to_string())?;
        }

        Ok(())
    }

    #[cfg(not(feature = "signature-cosign"))]
    async fn allows_image(&self, image: &mut Image, auth: &RegistryAuth) -> Result<()> {
        bail!("feature \"signature-cosign\" not enabled.")
    }
}

#[cfg(feature = "signature-cosign")]
impl CosignParameters {
    /// Check whether this Policy Request Match Type (i.e., signed identity
    /// check type) for the reference is MatchRepository or ExactRepository.
    /// Because cosign-created signatures only contain a repository,
    /// so only matchRepository and exactRepository can be used to accept them.
    /// Other types are all to be denied.
    /// If it is neither of them, return `Error`. Otherwise, return `Ok()`
    fn check_reference_rule_types(&self) -> Result<()> {
        match &self.signed_identity {
            Some(rule) => match rule {
                PolicyReqMatchType::MatchRepository
                | PolicyReqMatchType::ExactRepository { .. } => Ok(()),
                p => Err(anyhow!("Denied by {:?}", p)),
            },
            None => Ok(()),
        }
    }

    /// Verify the cosign-signed image. There will be three steps:
    /// * Get the pub key.
    /// * Download the cosign-signed image's manifest and its digest. Calculate its
    /// signature's image.
    /// * Download the signature image, gather the signatures and verify them
    /// using the pubkey.
    /// If succeeds, the payloads of the signature will be returned.
    async fn verify_signature_and_get_payload(
        &self,
        image: &Image,
        auth: &RegistryAuth,
    ) -> Result<Vec<SigPayload>> {
        // Get the pubkey
        let key = match (&self.key_data, &self.key_path) {
            (None, None) => bail!("Neither keyPath nor keyData is specified."),
            (None, Some(key_path)) => resource::get_resource(key_path).await?,
            (Some(key_data), None) => key_data.as_bytes().to_vec(),
            (Some(_), Some(_)) => bail!("Both keyPath and keyData are specified."),
        };

        let image_ref = OciReference::from_str(&image.reference.whole())?;
        let auth = &Auth::from(auth);

        let mut client = ClientBuilder::default().build()?;

        // Get the cosign signature "image"'s uri and the signed image's digest
        let (cosign_image, source_image_digest) = client.triangulate(&image_ref, auth).await?;

        let signature_layers = client
            .trusted_signature_layers(auth, &source_image_digest, &cosign_image)
            .await?;

        // By default, the hashing algorithm is SHA256
        let pub_key_verifier =
            PublicKeyVerifier::new(&key, &SigningScheme::ECDSA_P256_SHA256_ASN1)?;

        let verification_constraints: VerificationConstraintVec = vec![Box::new(pub_key_verifier)];

        let res = verify_constraints(&signature_layers, verification_constraints.iter());

        match res {
            Ok(()) => {
                // gather the payloads
                let payloads = signature_layers
                    .iter()
                    .map(|layer| SigPayload::from(layer.simple_signing.clone()))
                    .collect();
                Ok(payloads)
            }
            Err(SigstoreVerifyConstraintsError {
                unsatisfied_constraints,
            }) => Err(anyhow!("{:?}", unsatisfied_constraints)),
        }
    }
}

#[cfg(feature = "signature-cosign")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{
        mechanism::SignScheme,
        policy::{policy_requirement::PolicyReqType, ref_match::PolicyReqMatchType},
    };

    use std::convert::TryFrom;

    use oci_distribution::Reference;
    use rstest::rstest;
    use serial_test::serial;

    // All the test images are the same image, but different
    // registry and repository
    const IMAGE_DIGEST: &str =
        "sha256:7bd0c945d7e4cc2ce5c21d449ba07eb89c8e6c28085edbcf6f5fa4bf90e7eedc";

    #[rstest]
    #[case(
        CosignParameters{
            key_path: Some(
                format!(
                    "{}/test_data/signature/cosign/cosign1.pub",
                    std::env::current_dir()
                        .expect("get current dir")
                        .to_str()
                        .expect("get current dir"),
                )
            ),
            key_data: None,
            signed_identity: None,
        },
        "registry.cn-hangzhou.aliyuncs.com/xynnn/cosign:latest",
    )]
    #[case(
        CosignParameters{
            key_path: Some(
                format!(
                    "{}/test_data/signature/cosign/cosign1.pub",
                    std::env::current_dir()
                        .expect("get current dir")
                        .to_str()
                        .expect("get current dir"),
                )
            ),
            key_data: None,
            signed_identity: None,
        },
        "registry-1.docker.io/xynnn007/cosign:latest",
    )]
    #[case(
        CosignParameters{
            key_path: Some(
                format!(
                    "{}/test_data/signature/cosign/cosign1.pub",
                    std::env::current_dir()
                        .expect("get current dir")
                        .to_str()
                        .expect("get current dir"),
                )
            ),
            key_data: None,
            signed_identity: None,
        },
        "quay.io/kata-containers/confidential-containers:cosign-signed",
    )]
    #[tokio::test]
    #[serial]
    async fn verify_signature_and_get_payload_test(
        #[case] parameter: CosignParameters,
        #[case] image_reference: &str,
    ) {
        let reference =
            Reference::try_from(image_reference).expect("deserialize OCI Reference failed.");
        let mut image = Image::default_with_reference(reference);
        image
            .set_manifest_digest(IMAGE_DIGEST)
            .expect("Set manifest digest failed.");
        let res = parameter
            .verify_signature_and_get_payload(
                &image,
                &oci_distribution::secrets::RegistryAuth::Anonymous,
            )
            .await;
        assert!(
            res.is_ok(),
            "failed test:\nparameter:  {:?}\nimage reference:  {}\nreason:  {:?}",
            parameter,
            image_reference,
            res,
        );
    }

    #[rstest]
    #[case(PolicyReqMatchType::MatchExact, false)]
    #[case(PolicyReqMatchType::MatchRepoDigestOrExact, false)]
    #[case(PolicyReqMatchType::MatchRepository, true)]
    #[case(PolicyReqMatchType::ExactReference{docker_reference: "".into()}, false)]
    #[case(PolicyReqMatchType::ExactRepository{docker_repository: "".into()}, true)]
    #[case(PolicyReqMatchType::RemapIdentity{prefix:"".into(), signed_prefix:"".into()}, false)]
    fn check_reference_rule_types_test(
        #[case] policy_match: PolicyReqMatchType,
        #[case] pass: bool,
    ) {
        let parameter = CosignParameters {
            key_path: None,
            key_data: None,
            signed_identity: Some(policy_match),
        };
        assert_eq!(parameter.check_reference_rule_types().is_ok(), pass);
    }

    #[rstest]
    #[case(
        &format!("\
            {{\
                \"type\": \"sigstoreSigned\",\
                \"keyPath\": \"{}/test_data/signature/cosign/cosign2.pub\"\
            }}", 
            std::env::current_dir().expect("get current dir").to_str().expect("get current dir")
        ),
        "registry.cn-hangzhou.aliyuncs.com/xynnn/cosign:latest",
        false,
        // If verified failed, the pubkey given to verify will be printed.
        "[PublicKeyVerifier { key: ECDSA_P256_SHA256_ASN1(VerifyingKey { inner: PublicKey { point: AffinePoint { x: FieldElement(0x4D1167C9BBBCDB6CC1C867394D50C1777D5C2FCC46374E6B07819141E8D2CFAF), y: FieldElement(0xDB4E43CA897D2EE05C70836839AF5DBEE8B62EC4B93563FB044D92551FE33EEE), infinity: 0 } } }) }]"
    )]
    #[case(
        &format!("\
            {{\
                \"type\": \"sigstoreSigned\",\
                \"keyPath\": \"{}/test_data/signature/cosign/cosign1.pub\",\
                \"signedIdentity\": {{\
                    \"type\": \"exactRepository\",\
                    \"dockerRepository\": \"registry-1.docker.io/xynnn007/cosign-err\"\
                }}\
            }}", 
            std::env::current_dir().expect("get current dir").to_str().expect("get current dir")
        ),
        // The repository of the given image's and the Payload's are different
        "registry-1.docker.io/xynnn007/cosign:latest",
        false,
        "Match reference failed.",
    )]
    #[case(
        &format!("\
            {{\
                \"type\": \"sigstoreSigned\",\
                \"keyPath\": \"{}/test_data/signature/cosign/cosign2.pub\"\
            }}", 
            std::env::current_dir().expect("get current dir").to_str().expect("get current dir")
        ),
        "quay.io/kata-containers/confidential-containers:cosign-signed",
        false,
        // If verified failed, the pubkey given to verify will be printed.
        "[PublicKeyVerifier { key: ECDSA_P256_SHA256_ASN1(VerifyingKey { inner: PublicKey { point: AffinePoint { x: FieldElement(0x4D1167C9BBBCDB6CC1C867394D50C1777D5C2FCC46374E6B07819141E8D2CFAF), y: FieldElement(0xDB4E43CA897D2EE05C70836839AF5DBEE8B62EC4B93563FB044D92551FE33EEE), infinity: 0 } } }) }]"
    )]
    #[case(
        &format!("\
            {{\
                \"type\": \"sigstoreSigned\",\
                \"keyPath\": \"{}/test_data/signature/cosign/cosign1.pub\",\
                \"signedIdentity\": {{\
                    \"type\": \"matchExact\"\
                }}\
            }}", 
            std::env::current_dir().expect("get current dir").to_str().expect("get current dir")
        ),
        "quay.io/kata-containers/confidential-containers:cosign-signed",
        false,
        // Only MatchRepository and ExactRepository are supported.
        "Denied by MatchExact",
    )]
    #[case(
        &format!("\
        {{\
            \"type\": \"sigstoreSigned\",\
            \"keyPath\": \"{}/test_data/signature/cosign/cosign1.pub\"\
            }}", 
        std::env::current_dir().expect("get current dir").to_str().expect("get current dir")),
        "registry.cn-hangzhou.aliyuncs.com/xynnn/cosign:signed",
        true,
        ""
    )]
    #[case(
        &format!("\
        {{\
            \"type\": \"sigstoreSigned\",\
            \"keyPath\": \"{}/test_data/signature/cosign/cosign1.pub\"\
        }}", 
        std::env::current_dir().expect("get current dir").to_str().expect("get current dir")),
        "registry-1.docker.io/xynnn007/cosign:latest",
        true,
        ""
    )]
    #[case(
        &format!("\
        {{\
            \"type\": \"sigstoreSigned\",\
            \"keyPath\": \"{}/test_data/signature/cosign/cosign1.pub\"\
        }}", 
        std::env::current_dir().expect("get current dir").to_str().expect("get current dir")),
        "quay.io/kata-containers/confidential-containers:cosign-signed",
        true,
        ""
    )]
    #[tokio::test]
    #[serial]
    async fn verify_signature(
        #[case] policy: &str,
        #[case] image_reference: &str,
        #[case] allow: bool,
        #[case] failed_reason: &str,
    ) {
        let policy_requirement: PolicyReqType =
            serde_json::from_str(policy).expect("deserialize PolicyReqType failed.");
        let reference = oci_distribution::Reference::try_from(image_reference)
            .expect("deserialize OCI Reference failed.");

        let mut image = Image::default_with_reference(reference);
        image
            .set_manifest_digest(IMAGE_DIGEST)
            .expect("Set manifest digest failed.");

        if let PolicyReqType::Cosign(scheme) = policy_requirement {
            let res = scheme
                .allows_image(
                    &mut image,
                    &oci_distribution::secrets::RegistryAuth::Anonymous,
                )
                .await;
            assert_eq!(
                res.is_ok(),
                allow,
                "test failed: \nimage: {}\npolicy:{}",
                image_reference,
                policy
            );
            if !allow {
                let err_msg = res.unwrap_err().to_string();
                assert_eq!(
                    err_msg, failed_reason,
                    "test failed: failed reason unmatched.\nneed:{}\ngot:{}",
                    failed_reason, err_msg
                );
            }
        } else {
            panic!("Must be a sigstoreSigned policy!");
        }
    }
}
