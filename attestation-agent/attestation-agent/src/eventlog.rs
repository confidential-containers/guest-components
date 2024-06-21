// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{fs::File, io::Write};

use anyhow::{Context, Result};
use const_format::concatcp;

/// AA's eventlog will be put into this parent directory
pub const EVENTLOG_PARENT_DIR_PATH: &str = "/run/attestation-agent";

/// AA's eventlog will be stored inside the file
pub const EVENTLOG_PATH: &str = concatcp!(EVENTLOG_PARENT_DIR_PATH, "/eventlog");

pub struct EventLog {
    file: File,
}

impl EventLog {
    pub fn new() -> Result<Self> {
        std::fs::create_dir_all(EVENTLOG_PARENT_DIR_PATH).context("create eventlog parent dir")?;
        let file = File::create(EVENTLOG_PATH).context("create eventlog")?;
        Ok(Self { file })
    }

    pub fn write_log(&mut self, log: &str) -> Result<()> {
        writeln!(&mut self.file, "{log}").context("failed to write log")?;
        self.file
            .flush()
            .context("failed to flush log to I/O media")?;
        Ok(())
    }
}
