// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod attestation;
pub mod getresource;
pub mod keyprovider;

#[cfg(feature = "ttrpc")]
pub mod ttrpc_protocol;

use crate::AttestationAgent;

pub const AGENT_NAME: &str = "attestation-agent";

#[cfg(feature = "ttrpc")]
const PROTOCOL: &str = "ttrpc";
#[cfg(feature = "grpc")]
const PROTOCOL: &str = "grpc";

lazy_static! {
    pub static ref ABOUT: String = {
        let aa_about = AttestationAgent::default().about();
        format!("Protocol: {PROTOCOL}\n{aa_about}")
    };
}
