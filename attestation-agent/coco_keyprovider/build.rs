// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use shadow_rs::{BuildPattern, ShadowBuilder};

fn main() -> shadow_rs::SdResult<()> {
    tonic_build::compile_protos("../protos/keyprovider.proto")?;
    ShadowBuilder::builder()
        .build_pattern(BuildPattern::RealTime)
        .build()?;
    Ok(())
}
