// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::vec::Vec;

use crate::image;

mod policy_requirement;
mod ref_match;

pub use ref_match::default_match_policy;
pub use ref_match::PolicyReferenceMatcher;

use policy_requirement::*;

#[derive(EnumString, Display, Debug, PartialEq)]
pub enum ErrorInfo {
    #[strum(to_string = "Match reference failed.")]
    ErrMatchReference,
    #[strum(to_string = "The policy requirement type name is Unknown.")]
    ErrUnknowPolicyReqType,
    #[strum(to_string = "The reference match policy type name is Unknown.")]
    ErrUnknownMatchPolicyType,
}

// Policy defines requirements for considering a signature, or an image, valid.
// The spec of it is defined in https://github.com/containers/image/blob/main/docs/containers-policy.json.5.md
#[derive(Deserialize)]
pub struct Policy {
    // `default` applies to any image which does not have a matching policy in Transports.
    // Note that this can happen even if a matching `PolicyTransportScopes` exists in `transports`.
    default: PolicyRequirements,
    transports: HashMap<String, PolicyTransportScopes>,
}

pub type PolicyRequirements = Vec<Box<dyn PolicyRequirement>>;
pub type PolicyTransportScopes = HashMap<String, PolicyRequirements>;

impl Policy {
    // Parse the JSON file of policy (policy.json).
    pub fn from_file(file_path: &str) -> Result<Self> {
        let policy_json_string = fs::read_to_string(file_path)?;
        let policy = serde_json::from_str::<Policy>(&policy_json_string)?;
        Ok(policy)
    }

    // Returns Ok(()) if the requirement allows running an image.
    // WARNING: This validates signatures and the manifest, but does not download or validate the
    // layers. Users must validate that the layers match their expected digests.
    pub fn is_image_allowed(&self, mut image: image::Image) -> Result<()> {
        // Get the policy set that matches the image.
        let reqs = self.requirements_for_image(&image);
        if reqs.is_empty() {
            return Err(anyhow!(
                "List of verification policy requirements must not be empty"
            ));
        }

        // The image must meet the requirements of each policy in the policy set.
        for req in reqs.iter() {
            req.is_image_allowed(&mut image)?;
        }

        Ok(())
    }

    // Get the set of signature schemes that need to be verified of the image.
    pub fn signature_schemes(&self, image: &image::Image) -> Vec<Option<String>> {
        let mut schemes = Vec::new();
        let reqs = self.requirements_for_image(&image);

        for req in reqs.iter() {
            schemes.push(req.signature_scheme());
        }

        schemes
    }

    // selects the appropriate requirements for the image from Policy.
    fn requirements_for_image(&self, image: &image::Image) -> &PolicyRequirements {
        // Get transport name of the image
        let transport_name = image.transport_name();

        if let Some(transport_scopes) = self.transports.get(&transport_name) {
            // Look for a full match.
            let identity = image.reference.whole();
            if let Some(reqs) = transport_scopes.get(&identity) {
                return reqs;
            }

            // Look for a match of the possible parent namespaces.
            for name in image::get_image_namespaces(&image.reference).iter() {
                if let Some(reqs) = transport_scopes.get(name) {
                    return reqs;
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
