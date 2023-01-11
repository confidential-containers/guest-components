// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate lazy_static;

use anyhow::*;
use attestation_agent::AttestationAgent;
use clap::{App, Arg};
use log::*;
use std::sync::Arc;

#[cfg(any(
    not(any(feature = "grpc", feature = "ttrpc")),
    // all(feature = "grpc", feature = "ttrpc"),
))]
compile_error!("One and exactly one feature of `grpc` or `ttrpc` must be enabled.");

mod rpc;

#[cfg(feature = "grpc")]
mod grpc;
#[cfg(feature = "ttrpc")]
mod ttrpc;

fn main() {
    env_logger::init();

    #[cfg(feature = "ttrpc")]
    ttrpc::ttrpc_main();

    #[cfg(feature = "grpc")]
    grpc::grpc_main().unwrap();

    loop {}
}
