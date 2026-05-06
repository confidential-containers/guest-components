// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Context, Result};
use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::packet::{OpsVersionSpecific, Packet, PacketParser};
use pgp::types::KeyDetails;

use crate::signature::payload::simple_signing::SigPayload;

const GPG_KEY_ID_BYTES_LENGTH: usize = 20;
const GPG_KEY_ID_SUFFIX_BYTES_LENGTH_IN_SIG: usize = 8;

// SigKeyIDs is a util helper struct, used to compare
// whether the keyID of the key which verified the signature
// is consistant with the keyID recorded in the signature itself.
#[derive(Default)]
struct SigKeyIDs {
    pub trusted_key_id: Vec<u8>,
    pub sig_info_key_id: Vec<u8>,
}

impl SigKeyIDs {
    pub fn validate(&self) -> Result<()> {
        if self.trusted_key_id.len() != GPG_KEY_ID_BYTES_LENGTH {
            bail!("Wrong GPG key ID length in pubkey ring");
        }
        if self.sig_info_key_id.len() != GPG_KEY_ID_SUFFIX_BYTES_LENGTH_IN_SIG {
            bail!("Wrong GPG key ID length in signature payload");
        }

        if self.sig_info_key_id
            == self.trusted_key_id
                [(GPG_KEY_ID_BYTES_LENGTH - GPG_KEY_ID_SUFFIX_BYTES_LENGTH_IN_SIG)..]
                .to_vec()
        {
            Ok(())
        } else {
            Err(
                anyhow!(
                    "Key ID not matched. trusted key id is: {:X?}, but key id in signature info is: {:X?}", 
                    &self.trusted_key_id,
                    &self.sig_info_key_id
                )
            )
        }
    }
}

/// Parsed contents of an OpenPGP one-pass signed message:
/// `(ops_issuer_key_id, literal_body, signature)`.
type SigPackets = (
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<pgp::packet::Signature>,
);

/// Collect `OnePassSignature`, `LiteralData`, and `Signature` packets from a
/// flat packet stream.  Returns `(ops_key_id, literal_body, signature)`.
fn collect_sig_packets(
    parser: impl Iterator<Item = pgp::errors::Result<Packet>>,
) -> Result<SigPackets> {
    let mut ops_key_id: Option<Vec<u8>> = None;
    let mut literal_body: Option<Vec<u8>> = None;
    let mut signature_packet: Option<pgp::packet::Signature> = None;

    for pkt in parser {
        let pkt = pkt.context("Failed to parse OpenPGP packet")?;
        match pkt {
            Packet::OnePassSignature(ops) => {
                if let OpsVersionSpecific::V3 { key_id } = ops.version_specific() {
                    ops_key_id = Some(key_id.as_ref().to_vec());
                }
            }
            Packet::LiteralData(lit) => {
                literal_body = Some(lit.data().to_vec());
            }
            Packet::Signature(sig) => {
                signature_packet = Some(sig);
            }
            Packet::CompressedData(compressed) => {
                // Atomic container signatures are often wrapped in a
                // compressed packet.  Decompress and recurse one level.
                let decompressor = compressed
                    .decompress()
                    .context("Failed to decompress signature packet")?;
                let (inner_ops, inner_lit, inner_sig) =
                    collect_sig_packets(PacketParser::new(decompressor))?;
                if inner_ops.is_some() {
                    ops_key_id = inner_ops;
                }
                if inner_lit.is_some() {
                    literal_body = inner_lit;
                }
                if inner_sig.is_some() {
                    signature_packet = inner_sig;
                }
            }
            _ => {}
        }
    }

    Ok((ops_key_id, literal_body, signature_packet))
}

// Verifies the input signature, and verifies its principal components match expected
// values, both as specified by rules, and returns the signature payload.
pub fn verify_sig_and_extract_payload(pubkey_ring: &[u8], sig: Vec<u8>) -> Result<SigPayload> {
    // Parse all public keys from the keyring, supporting both binary and
    // ASCII-armored (PEM-style) formats.
    let (pubkeys_iter, _headers) = SignedPublicKey::from_reader_many(pubkey_ring)?;
    let pubkeys: Vec<SignedPublicKey> = pubkeys_iter
        .collect::<pgp::errors::Result<Vec<_>>>()
        .context("Failed to parse public key ring")?;

    // Parse the raw OpenPGP packets from the signature blob.
    // An atomic container signature is a one-pass signed literal message with structure:
    //   (optionally wrapped in a CompressedData packet)
    //   [0] OnePassSignature  — contains issuer key ID
    //   [1] LiteralData       — the signed JSON payload
    //   [2] Signature         — the actual cryptographic signature
    let (ops_key_id, literal_body, signature_packet) =
        collect_sig_packets(PacketParser::new(sig.as_slice()))?;

    let sig_info_key_id = ops_key_id
        .ok_or_else(|| anyhow!("Signature format error: no OnePassSignature packet found"))?;
    let body =
        literal_body.ok_or_else(|| anyhow!("Signature format error: no literal field in it!"))?;
    let signature =
        signature_packet.ok_or_else(|| anyhow!("Signature format error: no Signature packet"))?;

    // Try to verify using each public key in the keyring.
    let mut validate_key_id = SigKeyIDs {
        sig_info_key_id,
        ..Default::default()
    };

    for pubkey in &pubkeys {
        if signature.verify(&pubkey.primary_key, &*body).is_ok() {
            let fp = pubkey.primary_key.fingerprint();
            validate_key_id.trusted_key_id = fp.as_bytes().to_vec();
            // If the cryptography verification passes, but the key IDs are inconsistent,
            // the verification failure is returned directly.
            validate_key_id.validate()?;
            break;
        }
    }

    if validate_key_id.trusted_key_id.is_empty() {
        bail!("signature verify failed! There is no pubkey can verify the signature!");
    }

    let body_message = String::from_utf8(body).context("Signature body is not valid UTF-8")?;
    let sig_payload = serde_json::from_str::<SigPayload>(&body_message)?;
    Ok(sig_payload)
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use crate::signature::policy::ref_match::PolicyReqMatchType;

    use super::*;
    use oci_client::Reference;
    use serde_json::json;

    const SIG_PAYLOAD_JSON: &str = r#"{
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

    fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
        if s.len().is_multiple_of(2) {
            (0..s.len())
                .step_by(2)
                .map(|i| {
                    s.get(i..i + 2)
                        .and_then(|sub| u8::from_str_radix(sub, 16).ok())
                })
                .collect()
        } else {
            None
        }
    }

    #[test]
    fn test_validate_key_id() {
        let tests_unexpect = &[SigKeyIDs {
            trusted_key_id: hex_to_bytes("AEAF51ED16475A565335439B77E5C166C87B344B").unwrap(),
            sig_info_key_id: hex_to_bytes("7EFD4C926F9311E2").unwrap(),
        }];

        let tests_expect = &[SigKeyIDs {
            trusted_key_id: hex_to_bytes("2183156095E072685518F8A97EFD4C926F9311E2").unwrap(),
            sig_info_key_id: hex_to_bytes("7EFD4C926F9311E2").unwrap(),
        }];

        for case in tests_unexpect.iter() {
            assert!(case.validate().is_err());
        }

        for case in tests_expect.iter() {
            assert!(case.validate().is_ok());
        }
    }

    #[test]
    fn test_sigpayload_validate() {
        let sig_payload = serde_json::from_str::<SigPayload>(SIG_PAYLOAD_JSON).unwrap();
        let match_policy_json = r#"{
            "type": "matchExact"
        }"#;
        let match_reference_policy: PolicyReqMatchType =
            serde_json::from_str(match_policy_json).unwrap();

        #[derive(Debug)]
        struct TestData<'a> {
            digest: &'a str,
            reference: Reference,
        }

        let tests_expect = &[TestData {
            digest: "sha256:69704ef328d05a9f806b6b8502915e6a0a4faa4d72018dc42343f511490daf8a",
            reference: Reference::try_from("quay.io/ali_os_security/alpine:latest").unwrap(),
        }];

        let tests_unexpect = &[TestData {
            digest: "sha256:abcdeef328d05a9f806b6b8502915e6a0a4faa4d72018dc42343f511490daf8a",
            reference: Reference::try_from("quay.io/example_user/alpine:tag1").unwrap(),
        }];

        for case in tests_expect.iter() {
            assert!(sig_payload
                .validate_signed_docker_manifest_digest(case.digest)
                .is_ok());

            assert!(sig_payload
                .validate_signed_docker_reference(&case.reference, &match_reference_policy)
                .is_ok());
        }

        for case in tests_unexpect.iter() {
            assert!(sig_payload
                .validate_signed_docker_manifest_digest(case.digest)
                .is_err());

            assert!(sig_payload
                .validate_signed_docker_reference(&case.reference, &match_reference_policy)
                .is_err());
        }
    }

    #[test]
    fn test_verify_sig_and_extract_payload() {
        let sig_payload_parsed = json!({
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

        let keyring_bytes_case_1 = ::std::fs::read("./test_data/signature/pubring.gpg").unwrap();
        let sig_bytes_case_1 =
            ::std::fs::read("./test_data/signature/signatures/signature-1").unwrap();

        let sig_payload_verified =
            verify_sig_and_extract_payload(&keyring_bytes_case_1, sig_bytes_case_1).unwrap();

        let sig_payload_verified = serde_json::to_value(sig_payload_verified).unwrap();

        assert_eq!(sig_payload_parsed, sig_payload_verified);
    }
}
