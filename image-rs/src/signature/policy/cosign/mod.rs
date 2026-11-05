// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Cosign verification

use anyhow::{Result, anyhow, bail};
use oci_client::secrets::RegistryAuth;

use sigstore::registry::{Certificate, ClientConfig};
#[cfg(feature = "signature-cosign")]
use sigstore::{
    cosign::{
        ClientBuilder, CosignCapabilities,
        verification_constraint::{PublicKeyVerifier, VerificationConstraintVec},
        verify_constraints,
    },
    errors::SigstoreVerifyConstraintsError,
    registry::{Auth, OciReference},
};
use std::{str::FromStr, sync::Arc};

use crate::{
    config::ProxyConfig,
    signature::{
        image::Image, payload::simple_signing::SigPayload, policy::ref_match::PolicyReqMatchType,
    },
};
use crate::{resource::ResourceProvider, signature::SignatureValidator};

use super::CosignParameters;

impl SignatureValidator {
    /// Judge whether an image is allowed by this SignScheme.
    pub(crate) async fn cosign_allows_image(
        &self,
        parameter: &CosignParameters,
        image: &Image,
        auth: &RegistryAuth,
    ) -> Result<()> {
        parameter
            .check_image_signature(
                self._resource_provider.clone(),
                image,
                auth,
                self.certificates.iter().collect(),
                self._proxy_config.as_ref(),
            )
            .await
    }
}

impl CosignParameters {
    async fn check_image_signature(
        &self,
        _resource_provider: Arc<ResourceProvider>,
        image: &Image,
        auth: &RegistryAuth,
        certificates: Vec<&Certificate>,
        proxy_config: Option<&ProxyConfig>,
    ) -> Result<()> {
        // Check before we access the network
        self.check_reference_rule_types()?;

        // Get the public key
        let key = match (&self.key_data, &self.key_path) {
            (None, None) => bail!("Neither keyPath nor keyData is specified."),
            (None, Some(key_path)) => _resource_provider.get_resource(key_path).await?,
            (Some(key_data), None) => key_data.as_bytes().to_vec(),
            (Some(_), Some(_)) => bail!("Both keyPath and keyData are specified."),
        };

        // Verification, will access the network
        let payloads = self
            .verify_signature_and_get_payload(image, auth, key, certificates, proxy_config)
            .await?;

        // check the reference rules (signed identity)
        for payload in payloads {
            if let Some(rule) = &self.signed_identity {
                payload.validate_signed_docker_reference(&image.reference, rule)?;
            }

            if payload
                .validate_signed_docker_manifest_digest(&image.manifest_digest.to_string())
                .is_err()
            {
                // If the image manifest digest does not match the digest in the signature,
                // and the image is a multi-arch image, check if the digest of the manifest list
                // matches the signature.
                if let Some(manifest_list_digest) = &image.manifest_list_digest {
                    payload.validate_signed_docker_manifest_digest(
                        &manifest_list_digest.to_string(),
                    )?;
                } else {
                    bail!("Manifest digest does not match signature.");
                }
            }
        }

        Ok(())
    }

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
    ///   signature's image.
    /// * Download the signature image, gather the signatures and verify them
    ///   using the pubkey.
    ///
    /// If succeeds, the payloads of the signature will be returned.
    #[allow(clippy::too_many_arguments)]
    async fn verify_signature_and_get_payload(
        &self,
        image: &Image,
        auth: &RegistryAuth,
        key: Vec<u8>,
        certificates: Vec<&Certificate>,
        proxy_config: Option<&ProxyConfig>,
    ) -> Result<Vec<SigPayload>> {
        let image_ref = OciReference::from_str(&image.reference.whole())?;
        let auth = match auth {
            RegistryAuth::Anonymous => Auth::Anonymous,
            RegistryAuth::Basic(username, pass) => Auth::Basic(username.clone(), pass.clone()),
            RegistryAuth::Bearer(token) => Auth::Bearer(token.clone()),
        };

        let mut config = ClientConfig {
            extra_root_certificates: certificates.into_iter().cloned().collect(),
            ..Default::default()
        };

        if let Some(proxy) = proxy_config {
            config.http_proxy = proxy.http_proxy.clone();
            config.https_proxy = proxy.https_proxy.clone();
            config.no_proxy = proxy.no_proxy.clone();
        }

        let mut client = ClientBuilder::default()
            .with_oci_client_config(config)
            .build()?;

        let signature_layers = client.trusted_signature_layers(&auth, &image_ref).await?;

        // Some cosign implementations leave newlines in the signature. Strip these out.
        let signature_layers: Vec<sigstore::cosign::SignatureLayer> = signature_layers
            .iter()
            .map(|layer| {
                let mut cleaned = layer.clone();
                if let Some(sig) = &cleaned.signature {
                    cleaned.signature = Some(sig.replace(['\n', '\r'], ""));
                }
                cleaned
            })
            .collect();

        let pub_key_verifier = PublicKeyVerifier::try_from(key.as_slice())
            .map_err(|e| anyhow!("failed to build public key verifier: {e}"))?;
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
    use crate::signature::policy::{
        policy_requirement::PolicyReqType, ref_match::PolicyReqMatchType,
    };

    use oci_client::Reference;
    use rstest::rstest;
    use serial_test::serial;
    use sigstore::crypto::{CosignVerificationKey, Signature, SigningScheme};

    #[test]
    fn ecdsa_fixture_pubkey_matches_some_scheme() {
        let path = format!(
            "{}/test_data/signature/cosign/cosign1.pub",
            std::env::current_dir()
                .expect("cwd")
                .to_str()
                .expect("utf8")
        );
        let key = std::fs::read(path).expect("read ECDSA fixture");
        assert!(
            PublicKeyVerifier::try_from(key.as_slice()).is_ok(),
            "ECDSA fixture pubkey should parse with PublicKeyVerifier::try_from",
        );
    }

    #[test]
    fn generated_rsa_pubkey_matches_some_scheme() {
        let signer = SigningScheme::RSA_PKCS1_SHA256(2048)
            .create_signer()
            .expect("create RSA signer");
        let pem = signer
            .to_sigstore_keypair()
            .expect("extract keypair")
            .public_key_to_pem()
            .expect("export RSA public key as PEM");

        assert!(
            PublicKeyVerifier::try_from(pem.as_bytes()).is_ok(),
            "RSA pubkey should parse with PublicKeyVerifier::try_from",
        );

        let msg = b"guest-components cosign unit test";
        let sig = signer.sign(msg).expect("sign message with RSA");

        let verification_key = CosignVerificationKey::try_from_pem(pem.as_bytes())
            .expect("RSA pubkey should parse with CosignVerificationKey::try_from_pem");
        assert!(
            verification_key
                .verify_signature(Signature::Raw(&sig), msg)
                .is_ok(),
            "RSA signature should verify with the auto-detected verification key",
        );

        let mismatched =
            CosignVerificationKey::from_pem(pem.as_bytes(), &SigningScheme::ECDSA_P256_SHA256_ASN1)
                .expect("mismatched scheme is no longer rejected at construction time");
        assert!(
            mismatched
                .verify_signature(Signature::Raw(&sig), msg)
                .is_err(),
            "RSA signature must not verify under the ECDSA P-256 scheme",
        );
    }

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
        "ghcr.io/confidential-containers/test-container-image-rs:cosign-signed",
        "sha256:10e0ec4c7663b5f9be6efd16d8ceec760efe5377b9a0762ef3f51101ac08b7e8",
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
        "ghcr.io/confidential-containers/test-container-image-rs:cosign-signed",
        "sha256:10e0ec4c7663b5f9be6efd16d8ceec760efe5377b9a0762ef3f51101ac08b7e8",
    )]
    #[case(
        CosignParameters{
            key_path: Some(
                format!(
                    "{}/test_data/signature/cosign/nv.pub",
                    std::env::current_dir()
                        .expect("get current dir")
                        .to_str()
                        .expect("get current dir"),
                )
            ),
            key_data: None,
            signed_identity: None,
        },
        "nvcr.io/nvidia/cuda:12.2.0-base-ubuntu22.04",
        "sha256:ecdf8549dd5f12609e365217a64dedde26ecda26da8f3ff3f82def6749f53051",
    )]
    #[tokio::test]
    #[serial]
    async fn verify_signature_and_get_payload_test(
        #[case] parameter: CosignParameters,
        #[case] image_reference: &str,
        #[case] image_digest: &str,
    ) {
        let reference =
            Reference::try_from(image_reference).expect("deserialize OCI Reference failed.");
        let mut image = Image::default_with_reference(reference);
        image
            .set_manifest_digest(image_digest)
            .expect("Set manifest digest failed.");
        let _resource_provider = ResourceProvider::default();

        let key = _resource_provider
            .get_resource(parameter.key_path.as_ref().unwrap())
            .await
            .unwrap();
        let res = parameter
            .verify_signature_and_get_payload(
                &image,
                &oci_client::secrets::RegistryAuth::Anonymous,
                key,
                vec![],
                None,
            )
            .await;
        assert!(
            res.is_ok(),
            "failed test:\nparameter:  {parameter:?}\nimage reference:  {image_reference}\nreason:  {res:?}",
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
                \"keyPath\": \"{}/test_data/signature/cosign/cosign1.pub\",\
                \"signedIdentity\": {{\
                    \"type\": \"exactRepository\",\
                    \"dockerRepository\": \"registry-1.docker.io/xynnn007/cosign-err\"\
                }}\
            }}", 
            std::env::current_dir().expect("get current dir").to_str().expect("get current dir")
        ),
        // The repository of the given image's and the Payload's are different
        "ghcr.io/confidential-containers/test-container-image-rs:cosign-signed",
        "sha256:4f926abc2dc7b29781fd7870c7c91a1550f390fc86e10b7b3d5fa795eb5a3d39",
        false,
        "Match reference failed.",
    )]
    #[case(
        &format!("\
            {{\
                \"type\": \"sigstoreSigned\",\
                \"keyPath\": \"{}/test_data/signature/cosign/cosign3.pub\"\
            }}", 
            std::env::current_dir().expect("get current dir").to_str().expect("get current dir")
        ),
        "ghcr.io/confidential-containers/test-container-image-rs:cosign-signed",
        "sha256:4f926abc2dc7b29781fd7870c7c91a1550f390fc86e10b7b3d5fa795eb5a3d39",
        false,
        // Wrong key: the unsatisfied `PublicKeyVerifier` constraint is
        // reported through its Debug representation, whose internals changed
        // with the sigstore 0.14 upgrade, so only match the type name.
        "PublicKeyVerifier",
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
        "ghcr.io/confidential-containers/test-container-image-rs:cosign-signed",
        "sha256:4f926abc2dc7b29781fd7870c7c91a1550f390fc86e10b7b3d5fa795eb5a3d39",
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
        "ghcr.io/confidential-containers/test-container-image-rs:cosign-signed",
        "sha256:4f926abc2dc7b29781fd7870c7c91a1550f390fc86e10b7b3d5fa795eb5a3d39",
        true,
        ""
    )]
    #[tokio::test]
    #[serial]
    async fn verify_signature(
        #[case] policy: &str,
        #[case] image_reference: &str,
        #[case] image_digest: &str,
        #[case] allow: bool,
        #[case] failed_reason: &str,
    ) {
        let policy_requirement: PolicyReqType =
            serde_json::from_str(policy).expect("deserialize PolicyReqType failed.");
        let reference = oci_client::Reference::try_from(image_reference)
            .expect("deserialize OCI Reference failed.");

        let mut image = Image::default_with_reference(reference);
        image
            .set_manifest_digest(image_digest)
            .expect("Set manifest digest failed.");

        if let PolicyReqType::Cosign(scheme) = policy_requirement {
            let _resource_provider = ResourceProvider::default();
            let res = scheme
                .check_image_signature(
                    Arc::new(_resource_provider),
                    &image,
                    &oci_client::secrets::RegistryAuth::Anonymous,
                    vec![],
                    None,
                )
                .await;
            assert_eq!(
                res.is_ok(),
                allow,
                "test failed: \nimage: {image_reference}\npolicy:{policy}",
            );
            if !allow {
                let err_msg = res.unwrap_err().to_string();
                assert!(
                    err_msg.contains(failed_reason),
                    "test failed: failed reason unmatched.\nneed:{failed_reason}\ngot:{err_msg}",
                );
            }
        } else {
            panic!("Must be a sigstoreSigned policy!");
        }
    }
}
