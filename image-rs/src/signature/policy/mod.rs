// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use ref_match::PolicyReqMatchType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum_macros::{Display, EnumString};

use self::policy_requirement::PolicyReqType;

use super::image;

pub mod policy_requirement;
pub mod ref_match;

#[cfg(feature = "signature-cosign")]
pub mod cosign;

#[cfg(feature = "signature-simple")]
pub mod simple;

#[cfg(feature = "signature-simple")]
pub use simple::sigstore::SigstoreConfig;

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

#[derive(Deserialize, Debug, PartialEq, Eq, Serialize, Default)]
pub struct SimpleParameters {
    // KeyType specifies what kind of the public key to verify the signatures.
    #[serde(rename = "keyType")]
    pub key_type: String,

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

#[derive(EnumString, Display, Debug, PartialEq, Eq)]
pub enum ErrorInfo {
    #[strum(to_string = "Match reference failed.")]
    MatchReference,
    #[strum(to_string = "The policy requirement type name is Unknown.")]
    UnknowPolicyReqType,
    #[strum(to_string = "The reference match policy type name is Unknown.")]
    UnknownMatchPolicyType,
    #[strum(to_string = "The signature scheme is Unknown.")]
    UnknownScheme,
}

/// Policy defines requirements for considering a signature, or an image, valid.
/// The spec of it is defined in https://github.com/containers/image/blob/main/docs/containers-policy.json.5.md
#[derive(Deserialize)]
pub struct Policy {
    /// `default` applies to any image which does not have a matching policy in Transports.
    /// Note that this can happen even if a matching `PolicyTransportScopes` exists in `transports`.
    default: Vec<PolicyReqType>,
    transports: HashMap<String, PolicyTransportScopes>,
}

pub type PolicyTransportScopes = HashMap<String, Vec<PolicyReqType>>;

impl Policy {
    // selects the appropriate requirements for the image from Policy.
    pub(crate) fn requirements_for_image(&self, image: &image::Image) -> &Vec<PolicyReqType> {
        // Get transport name of the image
        let transport_name = image.transport_name();

        if let Some(transport_scopes) = self.transports.get(&transport_name) {
            // Look for a full match.
            let identity = image.reference.whole();
            if transport_scopes.contains_key(&identity) {
                return transport_scopes
                    .get(&identity)
                    .expect("Unexpected contains");
            }

            // Look for a match of the possible parent namespaces.
            for name in image::get_image_namespaces(&image.reference).iter() {
                if transport_scopes.contains_key(name) {
                    return transport_scopes.get(name).expect("Unexpected contains");
                }
            }

            // Look for a default match for the transport.
            if let Some(reqs) = transport_scopes.get("") {
                return reqs;
            }
        }

        &self.default
    }
}
