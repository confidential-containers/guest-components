// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod attestation;

#[cfg(feature = "ttrpc")]
pub mod ttrpc_protocol;

pub const AGENT_NAME: &str = "attestation-agent";

#[cfg(feature = "ttrpc")]
const PROTOCOL: &str = "ttrpc";
#[cfg(feature = "grpc")]
const PROTOCOL: &str = "grpc";

lazy_static! {
    pub static ref ABOUT: String = format!("Protocol: {PROTOCOL}");
}
