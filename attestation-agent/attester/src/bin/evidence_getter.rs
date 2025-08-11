// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use attester::{detect_attestable_devices, detect_tee_type, BoxedAttester};
use clap::Parser;
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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();
    // report_data on all platforms is 64 bytes length.
    let mut report_data = vec![0u8; 64];

    let cli = Cli::parse();

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

    let evidence = TryInto::<BoxedAttester>::try_into(detect_tee_type())
        .expect("Failed to initialize attester.")
        .get_evidence(report_data.clone())
        .await
        .expect("get evidence failed");
    println!("{:?}:{evidence}", detect_tee_type());

    for tee in detect_attestable_devices() {
        let attester =
            TryInto::<BoxedAttester>::try_into(tee).expect("Failed to initialize device attester");

        let evidence = attester
            .get_evidence(report_data.clone())
            .await
            .expect("get additional evidence failed");

        println!("{tee:?}:{evidence}");
    }
}
