// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io;

fn main() -> Result<(), io::Error> {
    tonic_build::compile_protos("../protos/keyprovider.proto")?;
    Ok(())
}
