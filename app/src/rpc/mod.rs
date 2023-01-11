// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod getresource;
pub mod keyprovider;

#[cfg(feature = "ttrpc")]
pub mod ttrpc_protocol;
#[cfg(feature = "ttrpc")]
pub type TtrpcService =
    std::collections::HashMap<String, Box<dyn ::ttrpc::MethodHandler + Send + Sync>>;

pub const AGENT_NAME: &str = "attestation-agent";
