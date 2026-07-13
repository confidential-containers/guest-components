// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Context, Result};
use attester::{detect_tee_type, BoxedAttester, InitDataResult};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(author)]
struct Cli {
    /// URL_SAFE_NO_PAD base64 encoded initdata digest.
    initdata: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let initdata = URL_SAFE_NO_PAD
        .decode(cli.initdata.as_bytes())
        .context("failed to decode initdata as URL_SAFE_NO_PAD base64")?;

    let tee = detect_tee_type();
    let attester = TryInto::<BoxedAttester>::try_into(tee)
        .context("failed to initialize attester for current platform")?;

    match attester
        .bind_init_data(&initdata)
        .await
        .context("failed to bind initdata")?
    {
        InitDataResult::Ok => println!("initdata bind success: {tee:?}"),
        InitDataResult::Unsupported => println!("initdata binding is unsupported on {tee:?}"),
    }

    Ok(())
}
