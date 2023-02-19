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

#[cfg(feature = "ttrpc")]
mod ttrpc;

#[cfg(feature = "grpc")]
mod grpc;

mod rpc;

fn main() {
    env_logger::init();

    cfg_if::cfg_if! {
        if #[cfg(feature = "ttrpc")] {
            ttrpc::ttrpc_main();
        } else if #[cfg(feature = "grpc")] {
            grpc::grpc_main().unwrap();
        } else {
            compile_error!("one feature of `grpc` or `ttrpc` must be enabled.");
        }
    }

    loop {}
}
