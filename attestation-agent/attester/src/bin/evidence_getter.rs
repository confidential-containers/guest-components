// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use attester::*;
use codicon::Read;

#[tokio::main]
async fn main() {
    // report_data on all platforms is 64 bytes length.
    let mut report_data = vec![0; 64];
    std::io::stdin()
        .read(&mut report_data)
        .expect("read input failed");

    let tee = detect_tee_type().expect("unknown tee type");
    let attester: BoxedAttester = tee.try_into().expect("create attester failed");
    let evidence = attester
        .get_evidence(report_data)
        .await
        .expect("get evidence failed");
    println!("{evidence}");
}
