// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use attester::{sgx_dcap::SgxDcapAttester, Attester};

fn real_main() -> Result<String> {
    let sgx_attester = SgxDcapAttester {};
    sgx_attester.get_evidence("test".into())
}

fn main() {
    match real_main() {
        std::result::Result::Ok(s) => println!("Get quote successfully: {s}"),
        Err(e) => eprintln!("Error: {e}"),
    }
}
