// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

mod sigstore;
mod verify;

pub use verify::verify_sig_and_extract_payload;
