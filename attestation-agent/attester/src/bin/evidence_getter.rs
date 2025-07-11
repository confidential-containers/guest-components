// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use attester::{detect_tee_type, BoxedAttester};
use clap::Parser;
use env_logger;
use std::io::Read;
use tokio::fs;

#[derive(Debug, Parser)]
#[command(author)]
enum Cli {
    /// Read report data from stdin. The input must be 64 bytes in length
    Stdio,

    /// Read report data from commandline. If the length of input is longer than
    /// 64 bytes, the input will be truncated. If shorter, it will be padded by `\0`.
    Commandline { data: String },

    /// Read report data from the given file. If the length of input is longer than
    /// 64 bytes, the input will be truncated. If shorter, it will be padded by `\0`.
    File { path: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logger for info/debug output
    env_logger::init();

    // report_data on all platforms is 64 bytes length.
    let mut report_data = vec![0u8; 64];

    let cli = Cli::parse();
    let primary_tee = detect_tee_type();
    let attester = BoxedAttester::try_from(primary_tee)?;

    match cli {
        Cli::Stdio => std::io::stdin()
            .read_exact(&mut report_data)
            .expect("read input failed"),
        Cli::Commandline { data } => {
            let len = data.len().min(64);
            report_data[..len].copy_from_slice(&data.as_bytes()[..len]);
        }
        Cli::File { path } => {
            let content = fs::read(path)
                .await
                .expect("read report data from file failed");
            let len = content.len().min(64);
            report_data[..len].copy_from_slice(&content[..len]);
        }
    }

    let evidence = attester.get_evidence(vec![]).await?;
    println!("{evidence}");
    Ok(())
}
