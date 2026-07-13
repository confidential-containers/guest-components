// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # KBS Clients
//!
//! There are two different kinds of KBS clients:
//! - `RCAR Client`: s.t. `KbsClient<Box<dyn EvidenceProvider>>`. It can
//!   perform RCAR handshaking, get token and get resource using the
//!   authenticated http session.
//! - `Token Client`: s.t. `KbsClient<Box<dyn TokenProvider>>`. It is a
//!   simpler client. It can only get resource with a valid token as its
//!   authentication materials.

#[cfg(feature = "background_check")]
pub mod rcar_client;

#[cfg(feature = "passport")]
pub mod token_client;

use kbs_types::Tee;

use crate::{keypair::TeeKeyPair, token_provider::Token};

pub(crate) enum ClientTee {
    Uninitialized,
    _Initialized(Tee),
}

/// This Client is used to connect to the remote KBS.
pub struct KbsClient<T> {
    /// TEE Type
    pub(crate) _tee: ClientTee,

    /// The asymmetric key pair inside the TEE
    pub(crate) tee_key: TeeKeyPair,

    pub(crate) provider: T,

    /// Http client
    pub(crate) http_client: reqwest::Client,

    /// KBS Host URL
    pub(crate) kbs_host_url: String,

    /// token
    pub(crate) token: Option<Token>,

    /// initdata toml plaintext (if any)
    pub(crate) _initdata: Option<String>,
}

pub const KBS_PROTOCOL_VERSION: &str = "0.4.0";

pub const KBS_GET_RESOURCE_MAX_ATTEMPT: u64 = 3;

pub const KBS_PREFIX: &str = "kbs/v0";
