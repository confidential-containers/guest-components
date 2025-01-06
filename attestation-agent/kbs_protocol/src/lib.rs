// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # The Client of KBS RCAR Protocol.
//!
//! This crate implements the client of a KBS RCAR Protocol, s.t. KBS Client.
//!
//! ## Protocol
//!
//! Please refer to <https://github.com/confidential-containers/kbs/blob/main/kbs/docs/kbs_attestation_protocol.md>
//!
//! ## Usage
//!
//! This crate supports two basic usages due to the [RATS model](https://datatracker.ietf.org/doc/rfc9334/).
//! - Background-Check Model
//! - Passport Model
//!
//! ### Background-Check Model
//!
//! In this model the request from the client for a resources is coupled with a
//! remote attestation process. An EvidenceProvider is needed to perform the
//! underlying RCAR handshake.
//!
//! Note: feature `background_check` must be enabled.
//!
//! ```no_run
//! use kbs_protocol::KbsClientBuilder;
//! use kbs_protocol::evidence_provider::NativeEvidenceProvider;
//! use kbs_protocol::KbsClientCapabilities;
//!
//! async fn background_check() {
//!     let evidence_provider = Box::new(NativeEvidenceProvider::new().unwrap());
//!     let mut client = KbsClientBuilder::with_evidence_provider(evidence_provider, "http://example.kbs.io")
//!         .build()
//!         .unwrap();
//!
//!     // the get_resource call will perform attestation
//!     let resource = client.get_resource("kbs:///default/key/1".try_into().unwrap()).await.unwrap();
//!
//!     // the client can also generate a token
//!     let (token, tee_key) = client.get_token().await.unwrap();
//! }
//! ```
//!
//! ### Passport Model
//!
//! Passport Model allows us to use a token provisioned by KBS to finish authentication.
//! The token certifies a tee key pair. The token and the tee keypair can be provided
//! by a TokenProvider.
//!
//! Note: feature `passport` must be enabled.
//!
//! ```no_run
//! use kbs_protocol::KbsClientBuilder;
//! use kbs_protocol::KbsClientCapabilities;
//! use kbs_protocol::token_provider::TestTokenProvider;
//!
//! async fn passport() {
//!     let token_provider = Box::<TestTokenProvider>::default();
//!     let mut client = KbsClientBuilder::with_token_provider(token_provider, "http://example.kbs.io")
//!         .build()
//!         .unwrap();
//!
//!     let resource = client.get_resource("kbs:///default/key/1".try_into().unwrap()).await.unwrap();
//! }
//! ```
//!
//! Note: everytime the token is found expired, the client will call the
//! `token_provider` to retrieve a new token.

pub mod api;
pub mod builder;
pub mod client;
pub mod error;
pub mod evidence_provider;
pub mod keypair;
pub mod token_provider;
#[cfg(feature = "aa_ttrpc")]
pub mod ttrpc_protos;

pub use api::*;
pub use builder::KbsClientBuilder;
pub use error::{Error, Result};
pub use keypair::TeeKeyPair;
pub use token_provider::Token;
