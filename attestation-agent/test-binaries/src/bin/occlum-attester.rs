// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use attester::{sgx_dcap::SgxDcapAttester, Attester};
use crypto::hash_chunks;

fn real_main() -> Result<String> {
    let sgx_attester = SgxDcapAttester {};
    sgx_attester.get_evidence("nonce".to_string(), "tee_data".to_string())
}

fn main() {
    match real_main() {
        std::result::Result::Ok(s) => println!("Get quote successfully: {s}"),
        Err(e) => eprintln!("Error: {e}"),
    }
}
