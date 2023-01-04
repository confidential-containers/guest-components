// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

fn main() -> std::io::Result<()> {
    tonic_build::compile_protos("./protos/getresource.proto")?;

    Ok(())
}
